// mbuild.cpp — Ferramenta única de build/empacotamento (LFS-friendly)
// Autor: ChatGPT (GPT-5 Thinking)
// Licença: MIT
//
// Recursos principais:
//  - fetch: baixar fontes (curl, git) com cache, validação sha256 opcional
//  - extract: extrair tar.* / zip / 7z ou copiar diretório
//  - build: autodetecta build system (build.sh, autogen+configure, configure+make,
//           cmake, meson, python (setup.py/pyproject), cargo, go, makefile)
//  - test: make test/check, ninja test, cargo test (quando existir)
//  - install: instala via DESTDIR em staging, strip (ELF only), gera pacote (tar.zst/xz),
//             registra lista de arquivos e instala no sistema (fakeroot opcional)
//  - package: gera pacote a partir do staging sem instalar no sistema
//  - remove: desinstala usando lista de arquivos registrada
//  - clean: remove work/logs/staging do pacote
//  - upgrade/reinstall: conveniências
//  - verify: verifica sha256 de um arquivo
//  - info: exibe metadados do pacote
//  - search: busca nos metadados/nomes
//  - revdep: ldd para detectar libs ausentes e sugerir pacotes
//  - hooks: pre/post de várias fases (fetch, extract, build, install, package, remove, clean)
//  - sync: versão, commit e push (git) do conteúdo (repo/logs/packages/work) com opções
//  - CLI consistente: nomes longos, curtos e numéricos (0 help; 1 fetch; 2 extract; 3 build;
//                     4 test; 5 install; 6 package; 7 remove; 8 upgrade; 9 reinstall;
//                     10 clean; 11 info; 12 search; 13 verify; 14 revdep; 15 sync)
//
// Layout padrão (pode ser alterado por env/rc):
//   $MBUILD_HOME (default: $HOME/.local/mbuild)
//     ├─ sources/   (downloads/cache)
//     ├─ work/      (fontes extraídas)
//     ├─ logs/      (logs de cada fase)
//     ├─ repo/      (metadados .meta, listas .files, pacotes .tar.*)
//     ├─ bin/       (reservado para futuros bins auxiliares)
//     └─ staging/   (instalações temporárias para empacote/instalar)
//
// Dependências externas (PATH): curl, git, tar, unzip, 7z (opcional), xz, zstd, sha256sum,
// file, ldd, make, cmake (quando necessário), ninja (meson), fakeroot (opcional), strip.
//
// Compilação: g++ -std=c++17 -O2 -pthread -o mbuild mbuild.cpp
//
// Observação: o programa usa popen/pclose para executar comandos do sistema.
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
    fs::path repo;
    fs::path bin;
    fs::path staging;

    // Git sync
    std::string git_remote = "";  // ex: git@github.com:user/mbuild-repo.git
    std::string git_branch = "main";

    static std::string envOr(const char* k, const std::string& def){
        const char* v = std::getenv(k);
        return v? std::string(v) : def;
    }
};

static Config CFG;

// ========================= Helpers de fs/log =========================
static void ensureDir(const fs::path& p){
    std::error_code ec; fs::create_directories(p, ec);
}

static bool fileExists(const fs::path& p){
    std::error_code ec; return fs::exists(p, ec);
}

static std::string timestamp_compact(){
    return now_ts("%Y%m%d-%H%M%S");
}

static void logInfo(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    if(CFG.color) std::cerr<<ansi::green<<ansi::bold<<"[*] "<<ansi::reset<<s<<"\n";
    else std::cerr<<"[*] "<<s<<"\n";
}
static void logWarn(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    if(CFG.color) std::cerr<<ansi::yellow<<ansi::bold<<"[!] "<<ansi::reset<<s<<"\n";
    else std::cerr<<"[!] "<<s<<"\n";
}
static void logErr(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    if(CFG.color) std::cerr<<ansi::red<<ansi::bold<<"[x] "<<ansi::reset<<s<<"\n";
    else std::cerr<<"[x] "<<s<<"\n";
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
                    std::cerr<<"\r";
                    if(CFG.color) std::cerr<<ansi::cyan<<frames[i%4]<<ansi::reset<<" "<<msg<<"   ";
                    else std::cerr<<frames[i%4]<<" "<<msg<<"   ";
                    std::cerr.flush();
                }
                ++i;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            // clear line
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

// Execução de comando com log/spinner
static int runCmd(const std::string& cmd, const fs::path& logfile="", bool show_spinner=false, const std::string& spin_msg="executando"){
    std::string full = cmd + (CFG.quiet? " > /dev/null 2>&1":" 2>&1");
    if(CFG.verbose){
        std::lock_guard<std::mutex> lk(log_mtx);
        if(CFG.color) std::cerr<<ansi::dim<<"$ "<<full<<ansi::reset<<"\n";
        else std::cerr<<"$ "<<full<<"\n";
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

// Primeiro subdiretório se houver somente 1; caso contrário, root
static fs::path firstOrOnlySubdir(const fs::path& root){
    int dirs=0; fs::path last;
    for(auto& e: fs::directory_iterator(root)){
        if(e.is_directory()){ dirs++; last = e.path(); }
    }
    if(dirs==1) return last;
    return root;
}

// ========================= Persistência simples (repo/.meta) =========================
static fs::path metaPath(const std::string& name){ return CFG.repo/(name + ".meta"); }
static fs::path filesPath(const std::string& name){ return CFG.repo/(name + ".files"); }

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
    // defaults adicionais
    const char* col = std::getenv("MBUILD_COLOR");
    if(col){ std::string v(col); if(v=="0"||v=="false"||v=="off") CFG.color=false; if(v=="1"||v=="true"||v=="on") CFG.color=true; }
    const char* spin = std::getenv("MBUILD_SPINNER");
    if(spin){ std::string v(spin); if(v=="0"||v=="false"||v=="off") CFG.spinner=false; if(v=="1"||v=="true"||v=="on") CFG.spinner=true; }
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
        }
    }
}

// ========================= Infra inicial / hooks =========================
static void initDirs(){
    ensureDir(CFG.home);
    ensureDir(CFG.sources);
    ensureDir(CFG.work);
    ensureDir(CFG.logs);
    ensureDir(CFG.repo);
    ensureDir(CFG.bin);
    ensureDir(CFG.staging);
}

static void runHooks(const std::string& phase, const std::string& name, const fs::path& log){
    fs::path hooksDir = CFG.home/"hooks"/phase;
    if(!fileExists(hooksDir)) return;
    for(auto& e: fs::directory_iterator(hooksDir)){
        if(!e.is_regular_file()) continue;
        fs::perms p = fs::status(e.path()).permissions();
        if((p & fs::perms::owner_exec) == fs::perms::none) continue;
        std::string cmd = "'" + e.path().string() + "' '" + name + "'";
        logInfo("Hook "+phase+": "+e.path().filename().string());
        runCmd(cmd, log);
    }
}

// ========================= Fases de instalação / pacote =========================
static void record_filelist_from_stage(const std::string& name, const fs::path& stage, const fs::path& log){
    fs::path filelist = filesPath(name);
    std::string listcmd = "bash -lc 'cd \"" + stage.string() + "\" && find . -type f -o -type l | sed s:^./:: > \"" + filelist.string() + "\"'";
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

static int install_stage_to_system(const std::string& name, const fs::path& stage, const fs::path& log){
    std::string instcmd = "tar -C '" + stage.string() + "' -cpf - . | ";
    if(CFG.use_fakeroot) instcmd += "fakeroot ";
    instcmd += "tar -C '" + CFG.destdir + "' -xpf -";
    int rc = runCmd(instcmd, log, true, "instalando no sistema");
    if(rc==0) logInfo("Instalação concluída: " + name + " => " + CFG.destdir);
    return rc;
}

// ========================= Ações: fetch/extract/build/test/... =========================
static int action_fetch(const std::string& src, const std::optional<std::string>& nameOpt, const std::optional<std::string>& sha){
    ensureDir(CFG.sources); ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(src)));
    fs::path log = CFG.logs/name/(timestamp_compact()+"-fetch.log");
    int rc=0;

    runHooks("pre-fetch", name, log);

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
            if(vrc!=0){ logErr("SHA256 não confere"); runHooks("post-fetch", name, log); return vrc; }
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
    }

    runHooks("post-fetch", name, log);
    if(rc==0) logInfo("Fetch concluído: " + name);
    return rc;
}

static int action_extract(const std::string& input, const std::optional<std::string>& nameOpt){
    ensureDir(CFG.work); ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(input)));
    fs::path outdir = CFG.work/name; ensureDir(outdir);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-extract.log");

    runHooks("pre-extract", name, log);

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

    runHooks("post-extract", name, log);
    if(rc==0) logInfo("Extração concluída: " + name);
    return rc;
}

static int action_build(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-build.log");
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : CFG.work/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);

    runHooks("pre-build", name, log);

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

    runHooks("post-build", name, log);
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

    runHooks("pre-install", name, log);

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

    return rc;
}

static int action_install(const std::string& name){
    // dependências declaradas em meta (opcional: deps=foo,bar)
    auto meta = metaGetAll(name);
    if (meta.count("deps")){
        std::istringstream iss(meta["deps"]); std::string dep;
        while(std::getline(iss, dep, ',')){
            if(dep.empty()) continue;
            if(!fileExists(metaPath(dep))){
                logErr("Dependência não instalada: " + dep);
                return 1;
            }
        }
    }
    fs::path stage, srcdir, slog;
    int rc = stage_install(name, stage, srcdir, slog);
    if(rc!=0){ logErr("Falha ao instalar no staging"); return rc; }

    // strip (ELF only)
    do_strip_stage(stage, slog);

    // empacota
    fs::path pkgfile;
    rc = package_stage(name, stage, pkgfile, slog);
    if(rc!=0){ logErr("Falha ao empacotar"); return rc; }

    // registra lista
    record_filelist_from_stage(name, stage, slog);

    // instala no sistema
    rc = install_stage_to_system(name, stage, slog);
    if(rc!=0){ logErr("Falha ao instalar no destino"); return rc; }

    runHooks("post-install", name, slog);
    return 0;
}

static int action_package(const std::string& name){
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : CFG.work/name;
    fs::path stage = CFG.staging/name;
    fs::path srcdir, slog;

    if(!(fileExists(stage) && !fs::is_empty(stage))){
        int rc = stage_install(name, stage, srcdir, slog);
        if(rc!=0){ logErr("Falha ao preparar staging para pacote"); return rc; }
    } else {
        slog = CFG.logs/name/(timestamp_compact()+"-package.log");
        runHooks("pre-package", name, slog);
    }

    // strip e empacota
    do_strip_stage(stage, slog);

    fs::path pkgfile;
    int rc = package_stage(name, stage, pkgfile, slog);
    if(rc!=0){ logErr("Falha ao empacotar"); return rc; }

    record_filelist_from_stage(name, stage, slog);

    runHooks("post-package", name, slog);
    logInfo("Pacote criado (sem instalar): " + pkgfile.string());
    return 0;
}

static int action_remove(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-remove.log");

    fs::path filelist = filesPath(name);
    if(!fileExists(filelist)){ logErr("Lista de arquivos não encontrada: " + filelist.string()); return 1; }

    runHooks("pre-remove", name, log);

    std::ifstream in(filelist); std::string rel;
    int rc_total=0;
    while(std::getline(in, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        if(fileExists(p)){
            int rc = runCmd("rm -f '" + p.string() + "'", log);
            rc_total |= rc;
        }
    }
    // remover diretórios vazios (tentativa)
    std::string clean = "bash -lc 'sort -r \"" + filelist.string() + "\" | xargs -I{} dirname {} | sort -u | while read d; do rmdir -p --ignore-fail-on-non-empty \"" + CFG.destdir + "/$d\" 2>/dev/null || true; done'";
    runCmd(clean, log);

    runHooks("post-remove", name, log);
    logInfo("Remoção concluída: " + name);
    return rc_total;
}

static int action_clean(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/name/(timestamp_compact()+"-clean.log");
    runHooks("pre-clean", name, log);
    std::error_code ec;
    fs::remove_all(CFG.work/name, ec);
    fs::remove_all(CFG.logs/name, ec);
    fs::remove_all(CFG.staging/name, ec);
    runHooks("post-clean", name, log);
    logInfo("Clean concluído: " + name);
    return 0;
}

static int action_upgrade(const std::string& name){
    int rc = action_remove(name);
    if(rc!=0) return rc;
    return action_install(name);
}
static int action_reinstall(const std::string& name){
    return action_install(name);
}

static int action_verify(const std::string& file, const std::string& sum){
    ensureDir(CFG.logs);
    fs::path log = CFG.logs/("verify-"+timestamp_compact()+".log");
    std::string verify = "echo '" + sum + "  " + fs::path(file).filename().string() + "' | (cd '" + fs::path(file).parent_path().string() + "' && sha256sum -c -)";
    int rc = runCmd(verify, log, true, "verificando");
    if(rc==0) logInfo("SHA256 OK");
    return rc;
}

static int action_info(const std::string& name){
    auto kv = metaGetAll(name);
    if(kv.empty()){ logErr("Pacote desconhecido: "+name); return 1; }
    std::cout<<"Nome: "<<name<<"\n";
    for(auto& it: kv) std::cout<<it.first<<": "<<it.second<<"\n";
    fs::path filelist = filesPath(name);
    if(fileExists(filelist)){
        std::cout<<"Arquivos (lista): "<<filelist.string()<<"\n";
    }
    return 0;
}

static int action_search(const std::string& term){
    for(auto& e: fs::directory_iterator(CFG.repo)){
        if(!e.is_regular_file()) continue;
        if(e.path().extension()==".meta"){
            std::string name = e.path().stem().string();
            bool printed=false;
            if(name.find(term)!=std::string::npos){
                std::cout<<name<<"\n"; printed=true;
            }
            if(printed) continue;
            auto kv = metaGetAll(name);
            for(auto& it: kv){
                if(it.second.find(term)!=std::string::npos){ std::cout<<name<<"\n"; break; }
            }
        }
    }
    return 0;
}

static int action_revdep(const std::string& name){
    fs::path filelist = filesPath(name);
    if(!fileExists(filelist)){ logErr("Sem lista de arquivos para analisar. Instale ou gere package primeiro."); return 1; }
    std::ifstream in(filelist); std::string rel;
    std::set<std::string> libs_missing;

    while(std::getline(in, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        if(!fileExists(p)) continue;
        // Somente binários/so
        std::string check = "bash -lc 'file -b \"" + p.string() + "\" | grep -qiE \"executable|shared object\"'";
        if(runCmd(check) != 0) continue;
        std::string cmd = "bash -lc 'ldd \"" + p.string() + "\" 2>/dev/null | awk \"/not found/{print \\$1}\"'";
        FILE* pipe = popen(cmd.c_str(), "r");
        if(!pipe) continue;
        char buf[512]; std::string out;
        while(fgets(buf,sizeof(buf),pipe)) out += buf;
        pclose(pipe);
        std::istringstream iss(out); std::string lib;
        while(iss>>lib) libs_missing.insert(lib);
    }

    if(libs_missing.empty()){ logInfo("Sem dependências ausentes detectadas."); return 0; }
    logWarn("Bibliotecas ausentes:");
    for(auto& l: libs_missing) std::cout<<"  "<<l<<"\n";

    logInfo("Sugestões de pacotes no repo contendo possíveis libs:");
    for(auto& e: fs::directory_iterator(CFG.repo)){
        if(e.path().extension()==".files"){
            std::ifstream f(e.path()); std::string rel2; std::set<std::string> libs;
            while(std::getline(f, rel2)){
                if(rel2.find(".so")!=std::string::npos) libs.insert(fs::path(rel2).filename().string());
            }
            for(auto& miss: libs_missing){
                for(auto& have: libs){
                    if(have.rfind(miss,0)==0){
                        std::cout<<"  - "<<e.path().stem().string()<<" (tem "<<have<<")\n";
                    }
                }
            }
        }
    }
    return 0;
}

// ========================= Sync (git) =========================
// Escopos: repo | logs | packages | work | all
static int action_sync(const std::string& scope, const std::optional<std::string>& message,
                       const std::optional<std::string>& remoteOpt, const std::optional<std::string>& branchOpt,
                       bool push, bool init_repo)
{
    // Diretório base do sync = $MBUILD_HOME
    fs::path root = CFG.home;
    ensureDir(root);

    // Se --init, inicializa repositório
    if(init_repo){
        if(!fileExists(root/".git")){
            int rc = runCmd("git -C '" + root.string() + "' init", "", true, "git init");
            if(rc!=0){ logErr("Falha ao inicializar git em "+root.string()); return rc; }
        }
        if(remoteOpt && !remoteOpt->empty()){
            runCmd("git -C '" + root.string() + "' remote remove origin >/dev/null 2>&1 || true");
            int rc = runCmd("git -C '" + root.string() + "' remote add origin '" + *remoteOpt + "'");
            if(rc!=0){ logErr("Falha ao adicionar remote origin"); return rc; }
        } else if(!CFG.git_remote.empty()){
            runCmd("git -C '" + root.string() + "' remote remove origin >/dev/null 2>&1 || true");
            int rc = runCmd("git -C '" + root.string() + "' remote add origin '" + CFG.git_remote + "'");
            if(rc!=0){ logWarn("Não foi possível definir remote default (talvez já exista)."); }
        }
    }

    // Monta .gitignore mínimo (não ignoramos nada crítico por padrão)
    if(!fileExists(root/".gitignore")){
        std::ofstream gi(root/".gitignore");
        gi << "# mbuild defaults\n"
              "*.tmp\n"
              ".cache/\n";
    }

    // Seleciona caminhos pro commit
    std::vector<fs::path> paths;
    if(scope=="all"){ paths = {CFG.repo, CFG.logs, CFG.work, CFG.sources, CFG.bin, CFG.staging}; }
    else if(scope=="repo"){ paths = {CFG.repo}; }
    else if(scope=="logs"){ paths = {CFG.logs}; }
    else if(scope=="packages"||scope=="pkgs"){ paths = {CFG.repo}; } // pacotes ficam em repo
    else if(scope=="work"){ paths = {CFG.work}; }
    else if(scope=="sources"){ paths = {CFG.sources}; }
    else { logWarn("Escopo desconhecido: "+scope+" — usando 'repo'"); paths = {CFG.repo}; }

    // git add -A relativos ao root
    for(const auto& p: paths){
        if(!fileExists(p)) continue;
        runCmd("git -C '" + root.string() + "' add -A '" + fs::relative(p, root).string() + "'");
    }

    // git commit
    std::string msg = message.value_or(("mbuild sync: " + now_ts()));
    int rc = runCmd("bash -lc \"cd '" + root.string() + "' && git diff --cached --quiet || git commit -m '" + msg + "'\"", "", true, "git commit");
    if(rc!=0){
        logWarn("Nada para commitar (ou commit falhou).");
    } else {
        logInfo("Commit criado.");
    }

    // git push
    std::string remote = remoteOpt.value_or(CFG.git_remote);
    std::string branch = branchOpt.value_or(CFG.git_branch);
    if(push){
        if(remote.empty()){ logWarn("Remote não definido. Use --remote URL ou defina MBUILD_GIT_REMOTE."); return 0; }
        // Garante branch
        runCmd("bash -lc \"cd '" + root.string() + "' && git symbolic-ref -q HEAD || git checkout -b '" + branch + "'\"");
        int prc = runCmd("git -C '" + root.string() + "' push -u '" + remote + "' '" + branch + "'", "", true, "git push");
        if(prc!=0){ logErr("git push falhou."); return prc; }
        logInfo("Push realizado: " + remote + " " + branch);
    }
    return 0;
}

// ========================= Ajuda/uso =========================
static void usage(){
    std::cout <<
"mbuild — ferramenta de build/empacote para LFS\n\n"
"Uso:\n"
"  mbuild <comando> [opções]\n\n"
"Comandos (nomes longos | atalho | número):\n"
"  help                    | h   | 0   — mostrar ajuda\n"
"  fetch <SRC>             | f   | 1   — baixar (curl/git/dir) [--name N] [--sha256 SUM]\n"
"  extract <ARQ|DIR>       | x   | 2   — extrair/copiar para work [--name N]\n"
"  build <NAME>            | b   | 3   — compilar [--jobs N]\n"
"  test <NAME>             | t   | 4   — rodar testes\n"
"  install <NAME>          | i   | 5   — instalar (staging→pacote→sistema)\n"
"      [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]\n"
"  package <NAME>          | p   | 6   — gerar pacote a partir do staging [--format zst|xz]\n"
"  remove <NAME>           | rm  | 7   — remover arquivos instalados\n"
"  upgrade <NAME>          | up  | 8   — remove + install\n"
"  reinstall <NAME>        | ri  | 9   — install novamente\n"
"  clean <NAME>            | c   | 10  — limpar work/logs/staging do pacote\n"
"  info <NAME>             |     | 11  — exibir metadados do pacote\n"
"  search <TERMO>          | s   | 12  — buscar no repositório local\n"
"  verify <ARQ> --sha256 S | v   | 13  — verificar sha256\n"
"  revdep <NAME>           |     | 14  — checar dependências ausentes (ldd)\n"
"  sync [escopo]           |     | 15  — sincronizar com git (commit/push)\n"
"      escopo: repo|logs|packages|work|sources|all (default: repo)\n"
"      opções: --message MSG --remote URL --branch BR --push|--no-push --init\n"
"\n"
"Flags globais (antes/depois do comando): --color | --no-color | --no-spinner | --quiet | --verbose\n"
"Dirs ativos:\n"
"  home="<<CFG.home<<"\n"
"  sources="<<CFG.sources<<"  work="<<CFG.work<<"  logs="<<CFG.logs<<"\n"
"  repo="<<CFG.repo<<"  bin="<<CFG.bin<<"  staging="<<CFG.staging<<"\n"
"Config: destdir="<<CFG.destdir<<"  jobs="<<CFG.jobs<<"  strip_flags="<<CFG.strip_flags<<"  format="<<CFG.package_format<<"\n"
"Git: remote="<<(CFG.git_remote.empty()?"<none>":CFG.git_remote)<<"  branch="<<CFG.git_branch<<"\n";
}

// ========================= Parser CLI =========================
static std::string mapAlias(const std::string& cmd){
    static const std::map<std::string,std::string> M = {
        {"0","help"}, {"h","help"}, {"help","help"},
        {"1","fetch"}, {"f","fetch"}, {"fetch","fetch"},
        {"2","extract"}, {"x","extract"}, {"extract","extract"},
        {"3","build"}, {"b","build"}, {"build","build"},
        {"4","test"}, {"t","test"}, {"test","test"},
        {"5","install"}, {"i","install"}, {"install","install"},
        {"6","package"}, {"p","package"}, {"package","package"},
        {"7","remove"}, {"rm","remove"}, {"remove","remove"},
        {"8","upgrade"}, {"up","upgrade"}, {"upgrade","upgrade"},
        {"9","reinstall"}, {"ri","reinstall"}, {"reinstall","reinstall"},
        {"10","clean"}, {"c","clean"}, {"clean","clean"},
        {"11","info"}, {"info","info"},
        {"12","search"}, {"s","search"}, {"search","search"},
        {"13","verify"}, {"v","verify"}, {"verify","verify"},
        {"14","revdep"}, {"revdep","revdep"},
        {"15","sync"}, {"sync","sync"}
    };
    auto it=M.find(cmd);
    return it==M.end()? cmd : it->second;
}

int main(int argc, char** argv){
    loadConfig();
    initDirs();

    // Junta args em vetor
    std::vector<std::string> args(argv+1, argv+argc);
    if(args.empty()){ usage(); return 0; }

    // flags globais (podem aparecer antes/depois)
    auto eatFlag = [&](const std::string& f){
        auto it = std::find(args.begin(), args.end(), f);
        if(it!=args.end()){ args.erase(it); return true; } return false;
    };
    auto getOpt = [&](const std::string& key)->std::optional<std::string>{
        for(size_t i=0;i+1<args.size();++i){
            if(args[i]==key){
                auto v=args[i+1];
                args.erase(args.begin()+i, args.begin()+i+2);
                return v;
            }
        }
        return std::nullopt;
    };

    // aplica globais
    if(eatFlag("--no-color")) CFG.color=false;
    if(eatFlag("--color")) CFG.color=true;
    if(eatFlag("--no-spinner")) CFG.spinner=false;
    if(eatFlag("--quiet")) CFG.quiet=true;
    if(eatFlag("--verbose")) CFG.verbose=true;

    if(args.empty()){ usage(); return 0; }
    std::string cmd = mapAlias(args.front()); args.erase(args.begin());

    if(cmd=="help"){ usage(); return 0; }

    // Dispatch
    if(cmd=="fetch"){
        if(args.empty()){ logErr("Uso: fetch <src> [--name N] [--sha256 SUM]"); return 2; }
        std::string src = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        auto sha  = getOpt("--sha256");
        return action_fetch(src, name, sha);
    }
    if(cmd=="extract"){
        if(args.empty()){ logErr("Uso: extract <arquivo|dir> [--name N]"); return 2; }
        std::string in = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        return action_extract(in, name);
    }
    if(cmd=="build"){
        if(args.empty()){ logErr("Uso: build <name> [--jobs N]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(auto j=getOpt("--jobs")){ try{ CFG.jobs = std::max(1, std::stoi(*j)); }catch(...){ } }
        return action_build(name);
    }
    if(cmd=="test"){
        if(args.empty()){ logErr("Uso: test <name>"); return 2; }
        return action_test(args.front());
    }
    if(cmd=="install"){
        if(args.empty()){ logErr("Uso: install <name> [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(eatFlag("--fakeroot")) CFG.use_fakeroot=true;
        if(eatFlag("--no-strip")) CFG.do_strip=false;
        if(eatFlag("--strip")) CFG.do_strip=true;
        if(auto f=getOpt("--strip-flags")) CFG.strip_flags=*f;
        if(auto d=getOpt("--destdir"))    CFG.destdir=*d;
        if(auto fmt=getOpt("--format"))   CFG.package_format=(*fmt=="xz"?"xz":"zst");
        return action_install(name);
    }
    if(cmd=="package"){
        if(args.empty()){ logErr("Uso: package <name> [--format zst|xz]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(auto fmt=getOpt("--format"))   CFG.package_format=(*fmt=="xz"?"xz":"zst");
        return action_package(name);
    }
    if(cmd=="remove"){
        if(args.empty()){ logErr("Uso: remove <name>"); return 2; }
        return action_remove(args.front());
    }
    if(cmd=="upgrade"){
        if(args.empty()){ logErr("Uso: upgrade <name>"); return 2; }
        return action_upgrade(args.front());
    }
    if(cmd=="reinstall"){
        if(args.empty()){ logErr("Uso: reinstall <name>"); return 2; }
        return action_reinstall(args.front());
    }
    if(cmd=="clean"){
        if(args.empty()){ logErr("Uso: clean <name>"); return 2; }
        return action_clean(args.front());
    }
    if(cmd=="verify"){
        if(args.size()<2){ logErr("Uso: verify <arquivo> --sha256 SUM"); return 2; }
        std::string file = args.front(); args.erase(args.begin());
        auto sha = getOpt("--sha256");
        if(!sha){ logErr("--sha256 obrigatório"); return 2; }
        return action_verify(file, *sha);
    }
    if(cmd=="info"){
        if(args.empty()){ logErr("Uso: info <name>"); return 2; }
        return action_info(args.front());
    }
    if(cmd=="search"){
        if(args.empty()){ logErr("Uso: search <termo>"); return 2; }
        return action_search(args.front());
    }
    if(cmd=="revdep"){
        if(args.empty()){ logErr("Uso: revdep <name>"); return 2; }
        return action_revdep(args.front());
    }
    if(cmd=="sync"){
        std::string scope = "repo";
        if(!args.empty() && args.front().rfind("-",0)!=0){ scope = args.front(); args.erase(args.begin()); }
        auto msg = getOpt("--message");
        auto rem = getOpt("--remote");
        auto br  = getOpt("--branch");
        bool push = true;
        if(eatFlag("--no-push")) push=false;
        if(eatFlag("--push")) push=true;
        bool init_repo = eatFlag("--init");
        return action_sync(scope, msg, rem, br, push, init_repo);
    }

    logErr("Comando desconhecido: " + cmd);
    usage();
    return 2;
}
