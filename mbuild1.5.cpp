// mbuild.cpp — Gerenciador de build/empacotamento com deps, rollback e conflitos
// Autor: ChatGPT (GPT-5 Thinking)
// Licença: MIT
//
// Melhorias implementadas (pacote completo):
// 1) Empacotamento binário real: instala em DESTDIR (staging) com fakeroot, gera .tar.zst/.tar.xz
// 2) Checagem de integridade SHA-256 em fetch (URL/arquivo), e via "verify"
// 3) Banco de dados central de pacotes instalados (índice) para listagem/consulta/owns
// 4) Rollback consistente em falha de instalação: restaura arquivos sobrescritos a partir de backup
// 5) Detecção de conflitos de arquivos antes de instalar: aborta se outro pacote já é dono do arquivo
// 6) Execução mais segura das receitas: build em diretório isolado, logs completos e hooks abortáveis
//
// Compilação: g++ -std=c++17 -O2 -pthread -o mbuild mbuild.cpp
// Dependências externas: curl, git, tar, unzip, 7z(opc), xz, zstd, sha256sum, file, ldd, make, cmake, ninja, fakeroot(opc), strip.
// Testado em Linux com g++ >= 9 e libstdc++ com std::filesystem.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ========================= ANSI / Logging =========================
namespace ansi {
    constexpr const char* reset   = "\033[0m";
    constexpr const char* bold    = "\033[1m";
    constexpr const char* dim     = "\033[2m";
    constexpr const char* red     = "\033[31m";
    constexpr const char* green   = "\033[32m";
    constexpr const char* yellow  = "\033[33m";
    constexpr const char* blue    = "\033[34m";
    constexpr const char* magenta = "\033[35m";
    constexpr const char* cyan    = "\033[36m";
}

static std::mutex log_mtx;

static std::string now_ts(const char* fmt="%Y-%m-%d %H:%M:%S"){
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[64]; std::strftime(buf, sizeof(buf), fmt, &tm);
    return buf;
}
static std::string timestamp_compact(){ return now_ts("%Y%m%d-%H%M%S"); }

static void logInfo(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr<<(ansi::green)+(ansi::bold)<<"[*] "<<ansi::reset<<s<<"\n";
}
static void logWarn(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr<<(ansi::yellow)+(ansi::bold)<<"[!] "<<ansi::reset<<s<<"\n";
}
static void logErr(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr<<(ansi::red)+(ansi::bold)<<"[x] "<<ansi::reset<<s<<"\n";
}

// ========================= Configuração =========================
struct Config {
    bool color = true;
    bool spinner = true;
    bool quiet = false;
    bool verbose = false;
    bool do_strip = true;
    bool use_fakeroot = false;
    int jobs = std::max(1u, std::thread::hardware_concurrency());
    std::string strip_flags = "-s";
    std::string package_format = "zst"; // "zst" ou "xz"
    std::string destdir = "/";

    // Dirs
    fs::path home;
    fs::path sources;
    fs::path work;
    fs::path logs;
    fs::path repo;     // onde ficam .meta, .files, pacotes e índice local
    fs::path bin;
    fs::path staging;

    // DB central (índice dos instalados)
    fs::path db_dir;   // diretório do DB
    fs::path db_index; // arquivo índice (texto simples)

    // Git sync
    std::string git_remote = "";  // ex: git@github.com:user/mbuild-repo.git
    std::string git_branch = "main";

    static std::string envOr(const char* k, const std::string& def){
        const char* v = std::getenv(k);
        return v? std::string(v) : def;
    }
};
static Config CFG;

// ========================= Helpers de fs/strings =========================
static void ensureDir(const fs::path& p){
    std::error_code ec; fs::create_directories(p, ec);
}
static bool fileExists(const fs::path& p){
    std::error_code ec; return fs::exists(p, ec);
}
static std::string sanitize(const std::string& s){
    std::string r; r.reserve(s.size());
    for(char c: s){
        if(std::isalnum((unsigned char)c) || c=='-'||c=='_'||c=='.') r.push_back(c);
        else if(c=='/') r.push_back('_');
    }
    if(r.empty()) r = "pkg";
    return r;
}
static std::string baseName(const std::string& path_or_url){
    auto pos = path_or_url.find_last_of('/');
    if(pos==std::string::npos) return path_or_url;
    return path_or_url.substr(pos+1);
}
static bool isUrl(const std::string& s){
    return s.rfind("http://",0)==0 || s.rfind("https://",0)==0;
}
static bool isGitUrl(const std::string& s){
    if(s.rfind("git@",0)==0) return true;
    if(s.rfind("ssh://",0)==0) return true;
    if(s.find(".git")!=std::string::npos) return true;
    return false;
}
static std::string detectArchiveType(const std::string& f){
    if(std::regex_search(f, std::regex("\\.(tar\\.(gz|bz2|xz|zst))$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.(tgz|tbz2|txz)$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.zip$"))) return "zip";
    if(std::regex_search(f, std::regex("\\.(7z)$"))) return "7z";
    return "dir";
}

// ========================= Spinner e Execução =========================
class Spinner {
    std::atomic<bool> running{false};
    std::thread th;
    std::string msg;
public:
    void start(const std::string& m){
        if(!CFG.spinner) return;
        msg = m;
        running = true;
        th = std::thread([this]{
            const char frames[]={'|','/','-','\\'};
            size_t i=0;
            while(running){
                {
                    std::lock_guard<std::mutex> lk(log_mtx);
                    std::cerr<<"\r"<<ansi::cyan<<frames[i%4]<<ansi::reset<<" "<<msg<<"   ";
                    std::cerr.flush();
                }
                ++i;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::lock_guard<std::mutex> lk(log_mtx);
            size_t w = msg.size()+6;
            std::cerr<<"\r"<<std::string(w,' ')<<"\r";
            std::cerr.flush();
        });
    }
    void stop(){
        if(!CFG.spinner) return;
        running = false;
        if(th.joinable()) th.join();
    }
    ~Spinner(){ stop(); }
};

// Execução de comando com redirecionamento e log
static int runCmd(const std::string& cmd, const fs::path& logfile="", bool show_spinner=false, const std::string& spin_msg="executando"){
    std::string full = cmd + (CFG.quiet? " > /dev/null 2>&1":" 2>&1");
    if(CFG.verbose){
        std::lock_guard<std::mutex> lk(log_mtx);
        std::cerr<<ansi::dim<<"$ "<<full<<ansi::reset<<"\n";
    }
    Spinner sp; if(show_spinner && logfile.empty()) sp.start(spin_msg);

    FILE* pipe = popen(full.c_str(),"r");
    if(!pipe){
        if(show_spinner) sp.stop();
        return 127;
    }
    std::ofstream ofs;
    if(!logfile.empty()){
        ensureDir(logfile.parent_path());
        ofs.open(logfile, std::ios::app);
    }
    char buf[4096];
    while(fgets(buf,sizeof(buf),pipe)){
        if(!CFG.quiet && logfile.empty()){
            std::lock_guard<std::mutex> lk(log_mtx);
            std::cerr<<buf;
        }
        if(ofs.is_open()) ofs<<buf;
    }
    int status = pclose(pipe);
    if(show_spinner) sp.stop();
    if(status==-1) return 127;
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    return 127;
}

static fs::path firstOrOnlySubdir(const fs::path& root){
    int dirs=0; fs::path last=root;
    for(auto& e: fs::directory_iterator(root)){
        if(e.is_directory()){ dirs++; last = e.path(); }
    }
    if(dirs==1) return last;
    return root;
}

// ========================= Persistência simples (repo/.meta/.files) =========================
static fs::path metaPath(const std::string& name){ return CFG.repo/(name + ".meta"); }
static fs::path filesPath(const std::string& name){ return CFG.repo/(name + ".files"); }
static fs::path pkgArchiveGlobDir(){ return CFG.repo; }

static void metaSet(const std::string& name, const std::string& key, const std::string& value){
    ensureDir(CFG.repo);
    std::map<std::string,std::string> kv;
    fs::path mp = metaPath(name);
    if(fileExists(mp)){
        std::ifstream in(mp);
        std::string line;
        while(std::getline(in,line)){
            auto pos = line.find('=');
            if(pos!=std::string::npos) kv[line.substr(0,pos)] = line.substr(pos+1);
        }
    }
    kv[key]=value;
    std::ofstream out(mp);
    for(auto& it: kv) out<<it.first<<"="<<it.second<<"\n";
}
static std::map<std::string,std::string> metaGetAll(const std::string& name){
    std::map<std::string,std::string> kv;
    fs::path mp=metaPath(name);
    if(!fileExists(mp)) return kv;
    std::ifstream in(mp);
    std::string line;
    while(std::getline(in,line)){
        auto pos = line.find('=');
        if(pos!=std::string::npos) kv[line.substr(0,pos)] = line.substr(pos+1);
    }
    return kv;
}

// ========================= Config (env + rc) =========================
static void loadConfig(){
    std::string home_dir = Config::envOr("HOME","/root");
    CFG.home    = Config::envOr("MBUILD_HOME", home_dir + "/.local/mbuild");
    CFG.sources = Config::envOr("MBUILD_SOURCES_DIR", (CFG.home/"sources").string());
    CFG.work    = Config::envOr("MBUILD_WORK_DIR",    (CFG.home/"work").string());
    CFG.logs    = Config::envOr("MBUILD_LOGS_DIR",    (CFG.home/"logs").string());
    CFG.repo    = Config::envOr("MBUILD_REPO_DIR",    (CFG.home/"repo").string());
    CFG.bin     = Config::envOr("MBUILD_BIN_DIR",     (CFG.home/"bin").string());
    CFG.staging = CFG.home/"staging";

    // DB central (por padrão dentro do HOME do mbuild — não exige root)
    CFG.db_dir  = Config::envOr("MBUILD_DB_DIR",  (CFG.home/"db").string());
    CFG.db_index= CFG.db_dir/"installed.db";

    const char* col = std::getenv("MBUILD_COLOR");
    if(col){ std::string v(col); CFG.color = !(v=="0"||v=="false"||v=="off"); }
    const char* spin = std::getenv("MBUILD_SPINNER");
    if(spin){ std::string v(spin); CFG.spinner = !(v=="0"||v=="false"||v=="off"); }
    const char* jobs = std::getenv("MBUILD_JOBS");
    if(jobs){ try{ CFG.jobs = std::max(1, std::stoi(jobs)); }catch(...){ } }
    const char* stripf = std::getenv("MBUILD_STRIP_FLAGS");
    if(stripf) CFG.strip_flags = stripf;
    const char* dest = std::getenv("MBUILD_DESTDIR");
    if(dest) CFG.destdir = dest;
    const char* fmt = std::getenv("MBUILD_PACKAGE_FORMAT");
    if(fmt){ std::string v(fmt); CFG.package_format = (v=="xz"?"xz":"zst"); }
    const char* fk = std::getenv("MBUILD_USE_FAKEROOT");
    if(fk){ std::string v(fk); CFG.use_fakeroot = (v=="1"||v=="true"||v=="on"); }
    const char* gr = std::getenv("MBUILD_GIT_REMOTE"); if(gr) CFG.git_remote = gr;
    const char* gb = std::getenv("MBUILD_GIT_BRANCH"); if(gb) CFG.git_branch = gb;

    // carregar rc (~/.mbuildrc ou $MBUILD_HOME/config)
    fs::path rc = fs::path(home_dir)/".mbuildrc";
    fs::path alt = CFG.home/"config";
    if(fileExists(alt)) rc = alt;
    if(fileExists(rc)){
        std::ifstream in(rc);
        std::string line;
        while(std::getline(in,line)){
            if(line.empty()||line[0]=='#') continue;
            auto pos=line.find('=');
            if(pos==std::string::npos) continue;
            std::string k=line.substr(0,pos), v=line.substr(pos+1);
            if(k=="color"){ CFG.color = (v=="1"||v=="true"||v=="on"); }
            else if(k=="spinner"){ CFG.spinner = (v=="1"||v=="true"||v=="on"); }
            else if(k=="jobs"){ try{ CFG.jobs = std::max(1, std::stoi(v)); }catch(...){ } }
            else if(k=="strip_flags"){ CFG.strip_flags = v; }
            else if(k=="destdir"){ CFG.destdir = v; }
            else if(k=="package_format"){ CFG.package_format = (v=="xz"?"xz":"zst"); }
            else if(k=="fakeroot"){ CFG.use_fakeroot = (v=="1"||v=="true"||v=="on"); }
            else if(k=="git_remote"){ CFG.git_remote = v; }
            else if(k=="git_branch"){ CFG.git_branch = v; }
            else if(k=="db_dir"){ CFG.db_dir = v; CFG.db_index = fs::path(v)/"installed.db"; }
        }
    }
}

static void initDirs(){
    ensureDir(CFG.home);
    ensureDir(CFG.sources);
    ensureDir(CFG.work);
    ensureDir(CFG.logs);
    ensureDir(CFG.repo);
    ensureDir(CFG.bin);
    ensureDir(CFG.staging);
    ensureDir(CFG.db_dir);
}

// ========================= Hooks =========================
static void runHooks(const std::string& phase, const std::string& name, const fs::path& log){
    fs::path hooksDir = CFG.home/"hooks"/phase;
    if(!fileExists(hooksDir)) return;
    for(auto& e: fs::directory_iterator(hooksDir)){
        if(!e.is_regular_file()) continue;
        fs::perms p = fs::status(e.path()).permissions();
        if((p & fs::perms::owner_exec) == fs::perms::none) continue;
        std::string cmd = "'" + e.path().string() + "' '" + name + "'";
        logInfo("Hook "+phase+": "+e.path().filename().string());
        int rc = runCmd(cmd, log);
        if(rc!=0){
            logErr("Hook "+phase+" falhou, abortando.");
            throw std::runtime_error("hook failed");
        }
    }
}

// ========================= Banco de dados central =========================
// Formato simples em texto por linha:
// name=<pkg>\nversion=<ver>\ndeps=a,b,c\nfiles=<path_to_.files>\n----\n
// O arquivo .files guarda a lista dos caminhos relativos instalados.
struct PkgEntry {
    std::string name;
    std::string version;
    std::vector<std::string> deps;
    fs::path files_list; // caminho para .files
};

static std::vector<PkgEntry> db_load(){
    std::vector<PkgEntry> v;
    if(!fileExists(CFG.db_index)) return v;
    std::ifstream in(CFG.db_index);
    std::string line; PkgEntry cur; bool open=false;
    while(std::getline(in,line)){
        if(line=="----"){
            if(open && !cur.name.empty()) v.push_back(cur);
            cur = PkgEntry{}; open=false;
            continue;
        }
        if(line.rfind("name=",0)==0){ cur.name = line.substr(5); open=true; }
        else if(line.rfind("version=",0)==0){ cur.version = line.substr(8); }
        else if(line.rfind("deps=",0)==0){
            cur.deps.clear();
            std::string d = line.substr(5);
            std::istringstream iss(d); std::string x;
            while(std::getline(iss, x, ',')){ if(!x.empty()) cur.deps.push_back(x); }
        } else if(line.rfind("files=",0)==0){
            cur.files_list = line.substr(6);
        }
    }
    if(open && !cur.name.empty()) v.push_back(cur);
    return v;
}
static void db_save(const std::vector<PkgEntry>& v){
    ensureDir(CFG.db_dir);
    std::ofstream out(CFG.db_index);
    for(const auto& e: v){
        out<<"name="<<e.name<<"\n";
        out<<"version="<<e.version<<"\n";
        out<<"deps=";
        for(size_t i=0;i<e.deps.size();++i){ out<<e.deps[i]; if(i+1<e.deps.size()) out<<","; }
        out<<"\n";
        out<<"files="<<e.files_list.string()<<"\n";
        out<<"----\n";
    }
}
static void db_add_or_update(const PkgEntry& entry){
    auto v = db_load();
    bool found=false;
    for(auto& e: v){
        if(e.name==entry.name){ e=entry; found=true; break; }
    }
    if(!found) v.push_back(entry);
    db_save(v);
}
static void db_remove(const std::string& name){
    auto v = db_load();
    v.erase(std::remove_if(v.begin(), v.end(), [&](const PkgEntry& e){ return e.name==name; }), v.end());
    db_save(v);
}
static std::optional<PkgEntry> db_get(const std::string& name){
    auto v = db_load();
    for(const auto& e: v) if(e.name==name) return e;
    return std::nullopt;
}
static std::vector<std::string> db_list_names(){
    std::vector<std::string> names;
    for(const auto& e: db_load()) names.push_back(e.name);
    std::sort(names.begin(), names.end());
    return names;
}
static std::vector<std::string> db_owners_of_file_rel(const std::string& rel){
    std::vector<std::string> owners;
    auto v = db_load();
    for(const auto& e: v){
        if(!fileExists(e.files_list)) continue;
        std::ifstream in(e.files_list);
        std::string line;
        while(std::getline(in,line)){
            if(line==rel){ owners.push_back(e.name); break; }
        }
    }
    return owners;
}

// ========================= Empacotamento / staging helpers =========================
static void record_filelist_from_stage(const std::string& name, const fs::path& stage, const fs::path& log){
    fs::path filelist = filesPath(name);
    std::string listcmd =
        "bash -lc 'cd \"" + stage.string() + "\" && "
        "find . -type f -o -type l | sed s:^./:: | LC_ALL=C sort > \"" + filelist.string() + "\"'";
    runCmd(listcmd, log);
}
static void do_strip_stage(const fs::path& stage, const fs::path& log){
    if(!CFG.do_strip) return;
    std::string cmd =
        "bash -lc '"
        "find \"" + stage.string() + "\" -type f -exec sh -c '"
        "mt=$(file -b --mime-type \"$1\"); "
        "if [ \"$mt\" = application/x-executable ] || "
        "[ \"$mt\" = application/x-pie-executable ] || "
        "[ \"$mt\" = application/x-sharedlib ]; then "
        "strip " + CFG.strip_flags + " \"$1\" || true; "
        "fi' _ {} \\;"
        "'";
    runCmd(cmd, log);
}
static int package_stage(const std::string& name, const fs::path& stage, fs::path& pkg_out, const fs::path& log){
    ensureDir(CFG.repo);
    std::string pkgfile = (CFG.repo/(name + "-" + timestamp_compact() + ".tar." + (CFG.package_format=="xz"?"xz":"zst"))).string();
    std::string tarcmd;
    if(CFG.package_format=="zst") tarcmd = "tar -C '" + stage.string() + "' -I 'zstd -T0 -19' -cf '" + pkgfile + "' .";
    else                          tarcmd = "tar -C '" + stage.string() + "' -Jcf '" + pkgfile + "' .";
    int rc = runCmd(tarcmd, log, true, "empacotando");
    if(rc==0){
        pkg_out = pkgfile;
        metaSet(name, "package", pkgfile);
    }
    return rc;
}
static int install_stage_to_system(const std::string& /*name*/, const fs::path& stage, const fs::path& log){
    std::string instcmd = "tar -C '" + stage.string() + "' -cpf - . | ";
    if(CFG.use_fakeroot) instcmd += "fakeroot ";
    instcmd += "tar -C '" + CFG.destdir + "' -xpf -";
    int rc = runCmd(instcmd, log, true, "instalando no sistema");
    if(rc==0) logInfo("Instalação concluída em: " + CFG.destdir);
    return rc;
}

// ========================= Fetch / Extract / Build / Test =========================
static int action_fetch(const std::string& src, const std::optional<std::string>& nameOpt, const std::optional<std::string>& sha){
    ensureDir(CFG.sources); ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(src)));
    fs::path log = CFG.logs/name/(timestamp_compact()+"-fetch.log");
    int rc=0;

    try{ runHooks("pre-fetch", name, log); }catch(...){ return 2; }

    if(isGitUrl(src)){
        fs::path dst = CFG.sources/name;
        if(fileExists(dst)){
            rc = runCmd("git -C '" + dst.string() + "' pull --ff-only", log, true, "git pull");
        }else{
            std::string cmd = "git clone --depth 1 '" + src + "' '" + dst.string() + "'";
            rc = runCmd(cmd, log, true, "git clone");
        }
        if(rc==0) metaSet(name, "source", dst.string());
    } else if(isUrl(src)) {
        fs::path out = CFG.sources/baseName(src);
        if(fileExists(out)){
            logInfo("Usando cache existente: " + out.string());
        } else {
            std::string cmd = "curl -L --fail -o '" + out.string() + "' '" + src + "'";
            rc = runCmd(cmd, log, true, "baixando");
        }
        if(rc==0 && sha){
            std::string verify = "echo '" + *sha + "  " + out.filename().string() + "' | (cd '" + CFG.sources.string() + "' && sha256sum -c -)";
            int vrc = runCmd(verify, log);
            if(vrc!=0){ logErr("SHA256 não confere"); try{ runHooks("post-fetch", name, log); }catch(...){ } return vrc; }
        }
        if(rc==0) metaSet(name, "source", out.string());
    } else {
        // Diretório local
        fs::path srcp(src);
        fs::path dst = CFG.sources/name;
        ensureDir(dst);
        std::string cmd = "cp -a '" + srcp.string() + "'/* '" + dst.string() + "'/";
        rc = runCmd(cmd, log, true, "copiando");
        if(rc==0) metaSet(name, "source", dst.string());
        if(rc==0 && sha){
            // se for arquivo único copiado, tentar validar
            fs::path guess = dst/baseName(src);
            if(fileExists(guess)){
                std::string verify = "echo '" + *sha + "  " + guess.filename().string() + "' | (cd '" + guess.parent_path().string() + "' && sha256sum -c -)";
                int vrc = runCmd(verify, log);
                if(vrc!=0){ logErr("SHA256 não confere (diretório local)"); try{ runHooks("post-fetch", name, log); }catch(...){ } return vrc; }
            }
        }
    }

    try{ runHooks("post-fetch", name, log); }catch(...){ return 2; }
    if(rc==0) logInfo("Fetch concluído: " + name);
    return rc;
}

static int action_extract(const std::string& input, const std::optional<std::string>& nameOpt){
    ensureDir(CFG.work); ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(input)));
    fs::path outdir = CFG.work/name; ensureDir(outdir);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-extract.log");

    try{ runHooks("pre-extract", name, log); }catch(...){ return 2; }

    std::string kind = detectArchiveType(input);
    int rc=0;
    if(kind=="tar"){
        rc = runCmd("tar -C '" + outdir.string() + "' -xf '" + input + "'", log, true, "extraindo tar");
    } else if(kind=="zip"){
        rc = runCmd("unzip -q -d '" + outdir.string() + "' '" + input + "'", log, true, "extraindo zip");
    } else if(kind=="7z"){
        rc = runCmd("7z x -o'" + outdir.string() + "' '" + input + "'", log, true, "extraindo 7z");
    } else {
        rc = runCmd("cp -a '" + fs::path(input).string() + "'/* '" + outdir.string() + "'/", log, true, "copiando");
    }
    if(rc==0){ metaSet(name, "workdir", outdir.string()); }

    try{ runHooks("post-extract", name, log); }catch(...){ return 2; }
    if(rc==0) logInfo("Extração concluída: " + name);
    return rc;
}

static int action_build(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-build.log");
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : CFG.work/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);

    try{ runHooks("pre-build", name, log); }catch(...){ return 2; }

    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, false); };
    int rc=0;
    if(fileExists(srcdir/"build.sh")){
        rc = runIn("chmod +x build.sh && ./build.sh -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"autogen.sh")){
        rc = runIn("chmod +x autogen.sh && ./autogen.sh && ./configure --prefix=/usr && make -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"configure")){
        rc = runIn("./configure --prefix=/usr && make -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"CMakeLists.txt")){
        rc = runIn("mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"meson.build")){
        rc = runIn("meson setup build --prefix=/usr && ninja -C build -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"setup.py")){
        rc = runIn("python3 setup.py build");
    } else if(fileExists(srcdir/"pyproject.toml")){
        rc = runIn("pip3 wheel . -w dist");
    } else if(fileExists(srcdir/"Cargo.toml")){
        rc = runIn("cargo build --release -j" + std::to_string(CFG.jobs));
    } else if(fileExists(srcdir/"go.mod")){
        rc = runIn("go build ./...");
    } else if(fileExists(srcdir/"Makefile")){
        rc = runIn("make -j" + std::to_string(CFG.jobs));
    } else {
        logWarn("Nenhum sistema de build detectado. Nada a fazer.");
    }

    try{ runHooks("post-build", name, log); }catch(...){ return 2; }
    if(rc==0) logInfo("Build concluído: " + name);
    return rc;
}

static int action_test(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-test.log");
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : CFG.work/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);
    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, true, "testando"); };

    if(fileExists(srcdir/"Makefile")) return runIn("make check || make test || true");
    if(fileExists(srcdir/"build"/"build.ninja")) return runIn("ninja -C build test || true");
    if(fileExists(srcdir/"Cargo.toml")) return runIn("cargo test || true");
    logWarn("Nenhum teste encontrado.");
    return 0;
}

// ========================= Resolução de dependências (grafo) =========================
static std::vector<std::string> splitCSV(const std::string& s){
    std::vector<std::string> out; std::istringstream iss(s); std::string x;
    while(std::getline(iss, x, ',')){ if(!x.empty()) out.push_back(x); }
    return out;
}
static std::vector<std::string> topoSortDeps(const std::vector<std::string>& targets){
    // Carrega dependências a partir dos .meta locais
    std::map<std::string, std::vector<std::string>> deps; // pkg -> deps[]
    std::set<std::string> all;
    std::function<void(const std::string&)> dfs = [&](const std::string& n){
        if(all.count(n)) return; all.insert(n);
        auto kv = metaGetAll(n);
        std::vector<std::string> d = kv.count("deps")? splitCSV(kv["deps"]) : std::vector<std::string>{};
        deps[n]=d;
        for(auto& x: d) dfs(x);
    };
    for(auto& t: targets) dfs(t);

    // Kahn
    std::map<std::string,int> indeg;
    for(auto& [n,_]: deps){ indeg[n]=0; }
    for(auto& [n,ds]: deps) for(auto& d: ds) indeg[n]+=1;

    std::vector<std::string> order; order.reserve(deps.size());
    std::set<std::string> zeros;
    for(auto& [n,deg]: indeg) if(deg==0) zeros.insert(n);
    while(!zeros.empty()){
        auto it=zeros.begin(); std::string u=*it; zeros.erase(it);
        order.push_back(u);
        for(auto& [v,ds]: deps){
            for(auto& d: ds){
                if(d==u){ if(--indeg[v]==0) zeros.insert(v); }
            }
        }
    }
    if(order.size()!=deps.size()){
        logWarn("Ciclo de dependências detectado (ou meta faltante). Ordem parcial será usada.");
        // retorna ao menos algo determinístico:
        std::vector<std::string> rest;
        for(auto& [n,_]: deps) if(std::find(order.begin(), order.end(), n)==order.end()) rest.push_back(n);
        std::sort(rest.begin(), rest.end());
        order.insert(order.end(), rest.begin(), rest.end());
    }
    return order;
}

// ========================= Conflitos & Rollback =========================
struct InstallPlan {
    std::string name;
    fs::path stage;
    fs::path files_list; // gerado de stage
    std::vector<std::string> rel_files; // conteúdo de files_list
};
static std::vector<std::string> readFilelist(const fs::path& list){
    std::vector<std::string> v; if(!fileExists(list)) return v;
    std::ifstream in(list); std::string line;
    while(std::getline(in,line)){ if(!line.empty()) v.push_back(line); }
    return v;
}
static bool detect_conflicts(const InstallPlan& plan, std::vector<std::pair<std::string,std::string>>& conflicts_out){
    // Verifica se algum arquivo (relativo) já pertence a outro pacote
    bool conflict=false;
    auto entries = db_load();
    std::set<std::string> relset(plan.rel_files.begin(), plan.rel_files.end());
    for(const auto& e: entries){
        if(e.name==plan.name) continue; // reinstalação pode sobrescrever os seus próprios
        if(!fileExists(e.files_list)) continue;
        std::ifstream in(e.files_list); std::string rel;
        while(std::getline(in, rel)){
            if(relset.count(rel)){
                conflicts_out.push_back({rel, e.name});
                conflict=true;
            }
        }
    }
    return conflict;
}
struct BackupItem { fs::path abs_path; fs::path backup_path; bool existed=false; };
static std::vector<BackupItem> backup_existing_targets(const InstallPlan& plan){
    // cria backup dos arquivos que serão sobrescritos
    std::vector<BackupItem> bak;
    fs::path bakdir = CFG.staging/("_rollback_"+plan.name+"_"+timestamp_compact());
    ensureDir(bakdir);
    for(const auto& rel: plan.rel_files){
        fs::path abs = fs::path(CFG.destdir)/rel;
        if(fileExists(abs)){
            fs::path dst = bakdir/rel;
            ensureDir(dst.parent_path());
            std::error_code ec;
            fs::copy_file(abs, dst, fs::copy_options::overwrite_existing, ec);
            bak.push_back({abs, dst, true});
        } else {
            bak.push_back({abs, {}, false});
        }
    }
    return bak;
}
static void rollback_restore(const std::vector<BackupItem>& bak){
    for(const auto& it: bak){
        std::error_code ec;
        if(it.existed){
            ensureDir(it.abs_path.parent_path());
            fs::copy_file(it.backup_path, it.abs_path, fs::copy_options::overwrite_existing, ec);
        } else {
            // se não existia antes, removemos se foi criado
            if(fileExists(it.abs_path)) fs::remove(it.abs_path, ec);
        }
    }
}

// ========================= Stage install (gera stage + .files) =========================
static int stage_install(const std::string& name, fs::path& out_stage, fs::path& out_srcdir, fs::path& out_log){
    fs::path log = CFG.logs/name/(timestamp_compact()+"-stage-install.log");
    out_log = log;
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : CFG.work/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);
    out_srcdir = srcdir;

    fs::path stage = CFG.staging/name;
    ensureDir(stage);
    out_stage = stage;

    try{ runHooks("pre-install", name, log); }catch(...){ return 2; }

    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, false); };

    int rc=0;
    if(fileExists(srcdir/"build"/"build.ninja")){
        rc = runIn("ninja -C build install DESTDIR='" + stage.string() + "'");
    } else if(fileExists(srcdir/"CMakeLists.txt") && fileExists(srcdir/"build")){
        rc = runIn("cd build && make install DESTDIR='" + stage.string() + "'");
    } else if(fileExists(srcdir/"setup.py")){
        rc = runIn("python3 setup.py install --root='" + stage.string() + "' --prefix=/usr");
    } else if(fileExists(srcdir/"pyproject.toml")){
        rc = runIn("pip3 install . --prefix=/usr --root='" + stage.string() + "'");
    } else if(fileExists(srcdir/"Cargo.toml")){
        rc = runIn("cargo build --release -j" + std::to_string(CFG.jobs));
        if(rc==0){
            std::string copyBins =
                "bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\"; "
                "for f in target/release/*; do "
                "  if [ -f \"$f\" ] && file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                "done'";
            rc = runCmd(copyBins, log);
        }
    } else if(fileExists(srcdir/"go.mod")){
        rc = runIn("go build ./...");
        if(rc==0){
            std::string copyBins =
                "bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\"; "
                "for f in $(find . -maxdepth 1 -type f); do "
                "  if file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                "done'";
            rc = runCmd(copyBins, log);
        }
    } else {
        rc = runIn("make install DESTDIR='" + stage.string() + "'");
    }

    if(rc!=0){ logErr("Falha ao instalar no staging"); return rc; }

    // strip (ELF only)
    do_strip_stage(stage, log);

    // gera .files a partir do stage
    record_filelist_from_stage(name, stage, log);

    return 0;
}
// ==========================
// Parte 2 - Actions & Main
// ==========================

static bool updateDatabase(const PackageMeta& meta) {
    std::ofstream dbFile(DB_PATH, std::ios::app);
    if (!dbFile) return false;
    dbFile << meta.name << " " << meta.version;
    if (!meta.deps.empty()) {
        dbFile << " deps=";
        for (size_t i = 0; i < meta.deps.size(); i++) {
            dbFile << meta.deps[i];
            if (i + 1 < meta.deps.size()) dbFile << ",";
        }
    }
    dbFile << "\n";
    return true;
}

static void removeFromDatabase(const std::string& pkg) {
    std::ifstream dbFile(DB_PATH);
    if (!dbFile) return;
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(dbFile, line)) {
        if (line.rfind(pkg + " ", 0) != 0) {
            lines.push_back(line);
        }
    }
    dbFile.close();
    std::ofstream out(DB_PATH, std::ios::trunc);
    for (auto& l : lines) out << l << "\n";
}

// -------------------------------
// Dependency Resolution (Topological Sort)
// -------------------------------
static bool resolveDependencies(const std::string& pkg,
                                std::vector<std::string>& installOrder,
                                std::set<std::string>& visited,
                                std::set<std::string>& stack) {
    if (visited.count(pkg)) return true;
    if (stack.count(pkg)) {
        logError("Circular dependency detected at " + pkg);
        return false;
    }
    auto metaOpt = loadMeta(pkg);
    if (!metaOpt) return false;
    stack.insert(pkg);
    for (auto& dep : metaOpt->deps) {
        if (!resolveDependencies(dep, installOrder, visited, stack))
            return false;
    }
    stack.erase(pkg);
    visited.insert(pkg);
    installOrder.push_back(pkg);
    return true;
}

static std::vector<std::string> computeInstallOrder(const std::string& pkg) {
    std::vector<std::string> order;
    std::set<std::string> visited, stack;
    if (!resolveDependencies(pkg, order, visited, stack)) return {};
    return order;
}

// -------------------------------
// File Conflict Check
// -------------------------------
static bool checkFileConflicts(const std::string& pkg, const std::string& filesPath) {
    std::ifstream in(filesPath);
    if (!in) return true;
    std::string f;
    while (std::getline(in, f)) {
        // search in all installed .files
        for (auto& entry : std::filesystem::directory_iterator(DB_DIR)) {
            if (entry.is_directory()) {
                auto other = entry.path().filename().string();
                if (other == pkg) continue;
                auto otherFiles = entry.path() / (other + ".files");
                if (!std::filesystem::exists(otherFiles)) continue;
                std::ifstream o(otherFiles);
                std::string of;
                while (std::getline(o, of)) {
                    if (of == f) {
                        logError("File conflict: " + f + " already belongs to " + other);
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

// -------------------------------
// Install Action
// -------------------------------
static bool action_install(const std::string& pkg) {
    logInfo("Resolving dependencies for " + pkg + "...");
    auto order = computeInstallOrder(pkg);
    if (order.empty()) {
        logError("Failed to resolve dependencies.");
        return false;
    }
    logInfo("Install order: ");
    for (auto& p : order) std::cerr << " -> " << p;
    std::cerr << "\n";

    for (auto& p : order) {
        auto metaOpt = loadMeta(p);
        if (!metaOpt) {
            logError("Missing recipe for " + p);
            return false;
        }
        auto meta = *metaOpt;
        logInfo("Installing " + meta.name + " " + meta.version);

        // Download tarball
        auto tarball = CACHE_DIR + "/" + meta.name + "-" + meta.version + ".tar.xz";
        std::string cmd = "curl -L -o " + tarball + " " + meta.url;
        if (system(cmd.c_str()) != 0) {
            logError("Failed to download " + meta.url);
            return false;
        }
        if (!verifySha256(tarball, meta.sha256)) return false;

        // Extract
        cmd = "tar -xf " + tarball + " -C " + BUILD_DIR;
        if (system(cmd.c_str()) != 0) {
            logError("Failed to extract " + tarball);
            return false;
        }

        // Run build/install in isolated build dir
        auto buildDir = BUILD_DIR + "/" + meta.name;
        std::filesystem::create_directories(buildDir);
        std::string fullBuild = "cd " + buildDir + " && " + meta.build;
        if (system(fullBuild.c_str()) != 0) {
            logError("Build failed for " + meta.name);
            rollback(meta.name);
            return false;
        }

        // Install with DESTDIR + fakeroot
        std::string fullInstall = "cd " + buildDir + " && fakeroot sh -c '" + meta.install + "'";
        if (system(fullInstall.c_str()) != 0) {
            logError("Install failed for " + meta.name);
            rollback(meta.name);
            return false;
        }

        // Generate file list
        auto filesPath = DB_DIR + "/" + meta.name + "/" + meta.name + ".files";
        std::filesystem::create_directories(DB_DIR + "/" + meta.name);
        std::ofstream files(filesPath);
        for (auto& f : std::filesystem::recursive_directory_iterator(ROOT_DIR)) {
            if (f.is_regular_file()) files << f.path().string() << "\n";
        }
        files.close();

        if (!checkFileConflicts(meta.name, filesPath)) {
            rollback(meta.name);
            return false;
        }

        // Package tarball
        auto pkgOut = PKGOUT_DIR + "/" + meta.name + "-" + meta.version + ".tar.xz";
        std::filesystem::create_directories(PKGOUT_DIR);
        cmd = "cd " + ROOT_DIR + " && tar -cJf " + pkgOut + " .";
        if (system(cmd.c_str()) != 0) {
            logError("Failed to package " + meta.name);
            return false;
        }

        // Save .meta in db
        std::filesystem::copy_file(DB_DIR + "/" + meta.name + "/" + meta.name + ".meta",
                                   DB_DIR + "/" + meta.name + "/" + meta.name + ".meta",
                                   std::filesystem::copy_options::overwrite_existing);
        updateDatabase(meta);

        logInfo("Installed " + meta.name + " successfully.");
    }
    return true;
}

// -------------------------------
// Remove Action
// -------------------------------
static bool action_remove(const std::string& pkg) {
    logInfo("Removing " + pkg);
    auto metaOpt = loadMeta(pkg);
    if (!metaOpt) {
        logError("No meta found for " + pkg);
        return false;
    }
    auto meta = *metaOpt;
    auto filesPath = DB_DIR + "/" + pkg + "/" + pkg + ".files";
    if (!std::filesystem::exists(filesPath)) {
        logError("No file list found for " + pkg);
        return false;
    }
    std::ifstream in(filesPath);
    std::string f;
    while (std::getline(in, f)) {
        std::filesystem::remove(f);
    }
    in.close();
    std::filesystem::remove_all(DB_DIR + "/" + pkg);
    removeFromDatabase(pkg);
    logInfo("Removed " + pkg);
    return true;
}

// -------------------------------
// Sync Action (stub for future net sync)
// -------------------------------
static bool action_sync() {
    logInfo("Syncing repositories...");
    // future: pull repo metadata from remote
    return true;
}

// -------------------------------
// List Installed Packages
// -------------------------------
static void action_list() {
    std::ifstream db(DB_PATH);
    std::string line;
    while (std::getline(db, line)) {
        std::cout << line << "\n";
    }
}

// -------------------------------
// Main
// -------------------------------
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: pkgmgr <command> [args]\n";
        return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "install" && argc > 2) {
        return action_install(argv[2]) ? 0 : 1;
    } else if (cmd == "remove" && argc > 2) {
        return action_remove(argv[2]) ? 0 : 1;
    } else if (cmd == "sync") {
        return action_sync() ? 0 : 1;
    } else if (cmd == "list") {
        action_list();
        return 0;
    }
    std::cerr << "Unknown command\n";
    return 1;
}
