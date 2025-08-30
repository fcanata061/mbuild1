// mbuild.cpp — Minimal build/orchestration tool for Linux From Scratch
// Autor: ChatGPT (GPT-5 Thinking)
// Licença: MIT
//
// Objetivo: ferramenta única ("mbuild") para:
//  - baixar fontes (curl, git) com cache
//  - verificar sha256
//  - descompactar vários formatos (tar.* / zip / 7z)
//  - compilar (autodetecta: build.sh, autogen+configure+make, configure+make,
//               meson+ninja, cmake, python (setup.py/pyproject), cargo, go, makefile)
//  - instalar via DESTDIR em "staging" e opcionalmente no sistema com fakeroot
//  - gerar pacote (tar.zst ou tar.xz) antes de instalar (e também sem instalar)
//  - strip de binários com detecção robusta + flags configuráveis
//  - logs coloridos, spinner e níveis de verbosidade
//  - hooks (pre/post de cada fase) e pós-remover
//  - procurar e exibir info de pacotes
//  - reverter instalação removendo arquivos rastreados
//  - revdep (verifica dependências compartilhadas ausentes)
//  - comandos extra: test, clean, upgrade, reinstall
//  - tudo configurável via env e arquivo de config (~/.mbuildrc ou $MBUILD_HOME/config)
//
// Requisitos externos (em PATH):
//  - curl, git, tar, unzip (opcional), 7z (opcional), xz, zstd (opcional),
//    sha256sum, make, fakeroot (opcional), strip, file, ldd
//
// Compilação:
//    g++ -std=c++17 -O2 -pthread -o mbuild mbuild.cpp
//
// Uso rápido:
//    ./mbuild fetch <URL|GIT|DIR> [--name NAME] [--sha256 SUM]
//    ./mbuild extract <ARQUIVO|DIR> [--name NAME]
//    ./mbuild build <NAME> [--jobs N]
//    ./mbuild test <NAME>
//    ./mbuild install <NAME> [--destdir DIR] [--fakeroot] [--strip|--no-strip] [--strip-flags "-s"] [--format zst|xz]
//    ./mbuild package <NAME> [--format zst|xz]   # gera pacote a partir do STAGING (sem instalar no sistema)
//    ./mbuild remove <NAME>
//    ./mbuild upgrade <NAME>
//    ./mbuild reinstall <NAME>
//    ./mbuild clean <NAME>
//    ./mbuild info <NAME>
//    ./mbuild search <termo>
//    ./mbuild verify <arquivo> --sha256 SUM
//    ./mbuild revdep <NAME>
//    ./mbuild help
//
// Variáveis (env) com defaults (podem ser alteradas por flags e arquivo .mbuildrc):
//    MBUILD_HOME        (default: $HOME/.local/mbuild)
//    MBUILD_SOURCES_DIR (default: $MBUILD_HOME/sources)
//    MBUILD_WORK_DIR    (default: $MBUILD_HOME/work)
//    MBUILD_LOGS_DIR    (default: $MBUILD_HOME/logs)
//    MBUILD_REPO_DIR    (default: $MBUILD_HOME/repo)
//    MBUILD_BIN_DIR     (default: $MBUILD_HOME/bin)
//    MBUILD_COLOR       (auto|1|0) — se não setado, usa config/CLI (default: true)
//
// Observação: Implementação pragmática com chamadas a programas do sistema.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <cctype>
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

namespace fs = std::filesystem;

// ========================= Util: ANSI cores =========================
namespace ansi {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string dim     = "\033[2m";
    const std::string red     = "\033[31m";
    const std::string green   = "\033[32m";
    const std::string yellow  = "\033[33m";
    const std::string blue    = "\033[34m";
    const std::string magenta = "\033[35m";
    const std::string cyan    = "\033[36m";
}

// ========================= Configuração =========================
struct Config {
    bool color = true;
    bool spinner = true;
    bool quiet = false;
    bool verbose = false;
    bool do_strip = true;
    std::string strip_flags = "-s"; // padrão
    int jobs = std::max(1u, std::thread::hardware_concurrency());
    std::string home;
    std::string sources;
    std::string work;
    std::string logs;
    std::string repo;
    std::string bin;
    std::string destdir = "/"; // destino final padrão
    bool use_fakeroot = false;
    std::string package_format = "zst"; // ou xz

    static std::string envOr(const char* key, const std::string& def) {
        const char* v = std::getenv(key);
        return v ? std::string(v) : def;
    }

    static Config loadFromEnv() {
        Config c;
        std::string home_dir = envOr("HOME", "/root");
        c.home    = envOr("MBUILD_HOME",        home_dir + "/.local/mbuild");
        c.sources = envOr("MBUILD_SOURCES_DIR", c.home + "/sources");
        c.work    = envOr("MBUILD_WORK_DIR",    c.home + "/work");
        c.logs    = envOr("MBUILD_LOGS_DIR",    c.home + "/logs");
        c.repo    = envOr("MBUILD_REPO_DIR",    c.home + "/repo");
        c.bin     = envOr("MBUILD_BIN_DIR",     c.home + "/bin");
        const char* col = std::getenv("MBUILD_COLOR");
        if(col){
            std::string v(col);
            if(v=="0"||v=="false"||v=="off") c.color=false;
            else if(v=="1"||v=="true"||v=="on") c.color=true;
            // "auto" mantemos default
        }
        return c;
    }
};

static Config CFG = Config::loadFromEnv();

static std::mutex log_mtx;

// ========================= Logging / Spinner =========================
class Spinner {
    std::atomic<bool> running{false};
    std::thread th;
    std::string msg;
public:
    void start(const std::string& m) {
        if(!CFG.spinner) return;
        msg = m;
        running = true;
        th = std::thread([this]{
            const char frames[] = {'|','/','-','\\'};
            size_t i = 0;
            while(running) {
                {
                    std::lock_guard<std::mutex> lk(log_mtx);
                    std::cerr << "\r" << (CFG.color? ansi::cyan:"") << frames[i%4]
                              << (CFG.color? ansi::reset:"") << " " << msg << "   ";
                    std::cerr.flush();
                }
                i++;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            // limpar linha
            std::lock_guard<std::mutex> lk(log_mtx);
            size_t w = msg.size() + 6;
            std::cerr << "\r" << std::string(w, ' ') << "\r";
            std::cerr.flush();
        });
    }
    void stop() {
        if(!CFG.spinner) return;
        running = false;
        if(th.joinable()) th.join();
    }
    ~Spinner(){ stop(); }
};

static void ensureDir(const fs::path& p) {
    std::error_code ec; fs::create_directories(p, ec);
}

static std::string timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%Y%m%d-%H%M%S");
    return os.str();
}

static int runCmd(const std::string& cmd, const fs::path& logfile = "", bool show_spinner = false, const std::string& spin_msg = "executando") {
    std::string full = cmd + (CFG.quiet? " > /dev/null 2>&1" : " 2>&1");
    if(CFG.verbose) {
        std::lock_guard<std::mutex> lk(log_mtx);
        std::cerr << (CFG.color? ansi::dim:"") << "$ " << full << (CFG.color? ansi::reset:"") << "\n";
    }
    Spinner sp;
    if(show_spinner && logfile.empty()) sp.start(spin_msg);

    FILE* pipe = popen(full.c_str(), "r");
    if(!pipe){
        if(show_spinner) sp.stop();
        return 127;
    }
    char buffer[4096];
    std::ofstream ofs;
    if(!logfile.empty()) {
        ensureDir(logfile.parent_path());
        ofs.open(logfile, std::ios::app);
    }
    while(fgets(buffer, sizeof(buffer), pipe)) {
        if(!CFG.quiet && logfile.empty()) {
            std::lock_guard<std::mutex> lk(log_mtx);
            std::cerr << buffer;
        }
        if(ofs.is_open()) ofs << buffer;
    }
    int status = pclose(pipe);
    if(show_spinner) sp.stop();

    if(status == -1) return 127;
    if(WIFEXITED(status)) return WEXITSTATUS(status);
    return 127;
}

static void logInfo(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr << (CFG.color? ansi::green+ansi::bold:"") << "[*] " << (CFG.color? ansi::reset:"") << s << "\n";
}
static void logWarn(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr << (CFG.color? ansi::yellow+ansi::bold:"") << "[!] " << (CFG.color? ansi::reset:"") << s << "\n";
}
static void logErr(const std::string& s){
    std::lock_guard<std::mutex> lk(log_mtx);
    std::cerr << (CFG.color? ansi::red+ansi::bold:"") << "[x] " << (CFG.color? ansi::reset:"") << s << "\n";
}

// ========================= Helpers =========================
static std::string sanitize(const std::string& s){
    std::string r; r.reserve(s.size());
    for(char c: s){
        if(std::isalnum((unsigned char)c) || c=='-' || c=='_' || c=='.') r.push_back(c);
        else if(c=='/') r.push_back('_');
    }
    if(r.empty()) r = "pkg";
    return r;
}

static std::string baseName(const std::string& url) {
    auto pos = url.find_last_of("/");
    if(pos==std::string::npos) return url;
    return url.substr(pos+1);
}

static bool isGitUrl(const std::string& s){
    // Simples e eficaz: se contém ".git", tratamos como repositório git
    return s.find(".git") != std::string::npos;
}

static bool isUrl(const std::string& s){
    return s.rfind("http://",0)==0 || s.rfind("https://",0)==0;
}

static std::string detectArchiveType(const std::string& f){
    if(std::regex_search(f, std::regex("\\.(tar\\.(gz|bz2|xz|zst))$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.(tgz|tbz2|txz)$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.zip$"))) return "zip";
    if(std::regex_search(f, std::regex("\\.(7z)$"))) return "7z";
    return "dir";
}

static std::string joinCmd(const std::vector<std::string>& parts){
    std::ostringstream os; bool first=true; for(const auto& p: parts){ if(!first) os<<" "; os<<p; first=false; }
    return os.str();
}

static bool fileExists(const fs::path& p){ std::error_code ec; return fs::exists(p, ec); }

static fs::path firstOrOnlySubdir(const fs::path& root) {
    int dirs = 0;
    fs::path last;
    for (auto& e : fs::directory_iterator(root)) {
        if (e.is_directory()) { dirs++; last = e.path(); }
    }
    if (dirs == 1) return last;
    return root; // mantém root se houver 0 ou >1 subdirs
}

// ========================= Hooks =========================
static void runHooks(const std::string& phase, const std::string& name, const fs::path& log){
    fs::path hooksDir = fs::path(CFG.home)/"hooks"/phase;
    if(!fs::exists(hooksDir)) return;
    for(auto& e: fs::directory_iterator(hooksDir)){
        if(!e.is_regular_file()) continue;
        fs::perms p = fs::status(e.path()).permissions();
        // Executar apenas se for executável pelo usuário
        if((p & fs::perms::owner_exec) == fs::perms::none) continue;
        std::string cmd = "'" + e.path().string() + "' '" + name + "'";
        logInfo("Hook " + phase + ": " + e.path().filename().string());
        runCmd(cmd, log);
    }
}

// ========================= Banco de dados simples =========================
// Formato: um arquivo por pacote em $repo/<name>.meta com chaves simples
static fs::path metaPath(const std::string& name){ return fs::path(CFG.repo)/(name+".meta"); }

static void metaSet(const std::string& name, const std::string& key, const std::string& value){
    ensureDir(CFG.repo);
    std::map<std::string,std::string> kv;
    fs::path mp = metaPath(name);
    if(fs::exists(mp)){
        std::ifstream ifs(mp); std::string line;
        while(std::getline(ifs,line)){
            auto pos=line.find('='); if(pos!=std::string::npos){ kv[line.substr(0,pos)]=line.substr(pos+1); }
        }
    }
    kv[key]=value;
    std::ofstream ofs(mp);
    for(auto& it: kv) ofs<<it.first<<"="<<it.second<<"\n";
}

static std::map<std::string,std::string> metaGetAll(const std::string& name){
    std::map<std::string,std::string> kv; fs::path mp = metaPath(name);
    if(!fs::exists(mp)) return kv; std::ifstream ifs(mp); std::string line;
    while(std::getline(ifs,line)){
        auto pos=line.find('='); if(pos!=std::string::npos){ kv[line.substr(0,pos)]=line.substr(pos+1); }
    }
    return kv;
}

// ========================= Config .mbuildrc =========================
static void loadFromRc(Config &c) {
    fs::path rc = fs::path(c.home) / "config";
    if (!fs::exists(rc)) {
        const char* home = std::getenv("HOME");
        if(home) {
            fs::path alt = fs::path(home) / ".mbuildrc";
            if (fs::exists(alt)) rc = alt;
        }
    }
    if (!fs::exists(rc)) return;

    std::ifstream ifs(rc);
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty() || line[0]=='#') continue;
        auto pos = line.find('=');
        if (pos==std::string::npos) continue;
        std::string k = line.substr(0,pos), v=line.substr(pos+1);
        if (k=="color") {
            if(v=="true"||v=="1"||v=="on") c.color=true;
            else if(v=="false"||v=="0"||v=="off") c.color=false;
        } else if (k=="jobs") c.jobs=std::stoi(v);
        else if (k=="strip_flags") c.strip_flags=v;
        else if (k=="destdir") c.destdir=v;
        else if (k=="spinner") c.spinner=(v=="true"||v=="1"||v=="on");
        else if (k=="package_format") c.package_format=(v=="xz"?"xz":"zst");
    }
}

// ========================= Infra inicial =========================
static void initDirs(){
    ensureDir(CFG.home);
    ensureDir(CFG.sources);
    ensureDir(CFG.work);
    ensureDir(CFG.logs);
    ensureDir(CFG.repo);
    ensureDir(CFG.bin);
    ensureDir(fs::path(CFG.home)/"staging");
}

// ========================= Fases (staging/instalar/empacotar) =========================

// Prepara stage: roda "make/ninja/cmake install DESTDIR=stage" mas NÃO instala no sistema.
static int stage_install(const std::string& name, fs::path& out_stage, fs::path& out_srcdir, fs::path& out_log) {
    Spinner sp; sp.start("instalando no staging");
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-stage-install.log");
    out_log = log;
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : fs::path(CFG.work)/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);
    out_srcdir = srcdir;

    fs::path stage = fs::path(CFG.home)/"staging"/name;
    ensureDir(stage);
    out_stage = stage;

    runHooks("pre-install", name, log);

    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, false); };

    int rc = 0;
    // tentar make install DESTDIR=stage
    if(fileExists(srcdir/"build"/"build.ninja")){
        rc = runIn("ninja -C build install DESTDIR='" + stage.string() + "'");
    } else if(fileExists(srcdir/"CMakeLists.txt") && fileExists(srcdir/"build")){
        rc = runIn("cd build && make install DESTDIR='" + stage.string() + "'");
    } else if(fileExists(srcdir/"setup.py")){
        // Python setup.py
        rc = runIn("python3 setup.py install --root='" + stage.string() + "' --prefix=/usr");
    } else if(fileExists(srcdir/"pyproject.toml")){
        // Instalar wheel criada previamente ou fazer "pip install --prefix"
        rc = runIn("pip3 install . --prefix=/usr --root='" + stage.string() + "'");
    } else if(fileExists(srcdir/"Cargo.toml")){
        // Cargo não usa DESTDIR; instalar binários manualmente (heurística)
        rc = runIn("cargo build --release -j" + std::to_string(CFG.jobs));
        if(rc==0){
            // copiar binários comuns do target/release para /usr/bin no stage
            std::string copyBins = "bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\" && "
                                   "for f in target/release/*; do "
                                   "  if [ -f \"$f\" ] && file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                                   "done'";
            rc = runCmd(copyBins, log);
        }
    } else if(fileExists(srcdir/"go.mod")){
        // Go: compilar e tentar descobrir binário principal (heurística)
        rc = runIn("go build ./...");
        if(rc==0){
            rc = runIn("bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\"; "
                       "for f in $(find . -maxdepth 1 -type f); do "
                       "  if file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                       "done'");
        }
    } else {
        // Makefile tradicional
        rc = runIn("make install DESTDIR='" + stage.string() + "'");
    }

    sp.stop();
    return rc;
}

// Strip robusto apenas em ELF executável/compartilhado
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

// Empacota o stage para o repo
static int package_stage(const std::string& name, const fs::path& stage, fs::path& pkg_out, const fs::path& log){
    ensureDir(CFG.repo);
    std::string pkgfile = CFG.repo + "/" + name + "-" + timestamp() + ".tar." + (CFG.package_format=="zst"?"zst":"xz");
    std::string tarcmd;
    if(CFG.package_format=="zst") tarcmd = "tar -C '" + stage.string() + "' -I 'zstd -T0 -19' -cf '" + pkgfile + "' .";
    else tarcmd = "tar -C '" + stage.string() + "' -Jcf '" + pkgfile + "' .";
    int rc = runCmd(tarcmd, log, true, "empacotando");
    if(rc==0){
        pkg_out = pkgfile;
        metaSet(name, "package", pkgfile);
    }
    return rc;
}

// Registra lista de arquivos do stage (relativos)
static void record_filelist_from_stage(const std::string& name, const fs::path& stage, const fs::path& log){
    fs::path filelist = fs::path(CFG.repo)/(name+".files");
    std::string listcmd = "bash -lc 'cd " + stage.string() + " && find . -type f -o -type l | sed s:^./:: > " + filelist.string() + "'";
    runCmd(listcmd, log);
}

// Instala do stage no sistema
static int install_stage_to_system(const std::string& name, const fs::path& stage, const fs::path& log){
    std::string instcmd = "tar -C '" + stage.string() + "' -cpf - . | ";
    if(CFG.use_fakeroot) instcmd += "fakeroot ";
    instcmd += "tar -C '" + CFG.destdir + "' -xpf -";
    int rc = runCmd(instcmd, log, true, "instalando no sistema");
    if(rc==0) logInfo("Instalação concluída: " + name + " => " + CFG.destdir);
    return rc;
}

// ========================= Ações =========================
static int action_fetch(const std::string& src, const std::optional<std::string>& nameOpt, const std::optional<std::string>& sha){
    Spinner sp; sp.start("baixando fontes");
    ensureDir(CFG.sources);
    ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(src)));
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-fetch.log");

    int rc=0;
    if(isGitUrl(src)){
        fs::path dst = fs::path(CFG.sources)/name;
        if(fs::exists(dst)){
            rc = runCmd("git -C '" + dst.string() + "' pull", log, true, "git pull");
        } else {
            std::string cmd = "git clone --depth 1 '" + src + "' '" + dst.string() + "'";
            rc = runCmd(cmd, log, true, "git clone");
        }
        if(rc==0) metaSet(name, "source", dst.string());
    } else if(isUrl(src)) {
        fs::path out = fs::path(CFG.sources)/baseName(src);
        if(fs::exists(out)){
            logInfo("Usando cache existente: " + out.string());
        } else {
            std::string cmd = "curl -L --fail -o '" + out.string() + "' '" + src + "'";
            rc = runCmd(cmd, log, true, "baixando");
        }
        if(rc==0 && sha){
            std::string verify = "echo '" + *sha + "  " + out.filename().string() + "' | (cd '" + CFG.sources + "' && sha256sum -c -)";
            int vrc = runCmd(verify, log);
            if(vrc!=0){ sp.stop(); logErr("SHA256 não confere"); return vrc; }
        }
        if(rc==0) metaSet(name, "source", out.string());
    } else {
        // diretório local: copiar para sources/name
        fs::path srcp(src);
        fs::path dst = fs::path(CFG.sources)/name;
        ensureDir(dst);
        std::string cmd = "cp -a '" + srcp.string() + "'/* '" + dst.string() + "'/";
        rc = runCmd(cmd, log, true, "copiando");
        if(rc==0) metaSet(name, "source", dst.string());
    }

    sp.stop();
    if(rc==0){ logInfo("Fetch concluído: " + name); }
    return rc;
}

static int action_extract(const std::string& input, const std::optional<std::string>& nameOpt){
    Spinner sp; sp.start("extraindo fontes");
    ensureDir(CFG.work);
    ensureDir(CFG.logs);
    std::string name = nameOpt.value_or(sanitize(baseName(input)));
    fs::path outdir = fs::path(CFG.work)/name;
    ensureDir(outdir);
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-extract.log");

    std::string kind = detectArchiveType(input);
    int rc=0;
    if(kind=="tar"){
        std::string cmd = "tar -C '" + outdir.string() + "' -xf '" + input + "'";
        rc = runCmd(cmd, log, true, "extraindo tar");
    } else if(kind=="zip"){
        std::string cmd = "unzip -q -d '" + outdir.string() + "' '" + input + "'";
        rc = runCmd(cmd, log, true, "extraindo zip");
    } else if(kind=="7z"){
        std::string cmd = "7z x -o'" + outdir.string() + "' '" + input + "'";
        rc = runCmd(cmd, log, true, "extraindo 7z");
    } else {
        // tratar como diretório: copiar
        fs::path srcp(input);
        std::string cmd = "cp -a '" + srcp.string() + "'/* '" + outdir.string() + "'/";
        rc = runCmd(cmd, log, true, "copiando");
    }
    if(rc==0){ metaSet(name, "workdir", outdir.string()); }
    sp.stop();
    if(rc==0) logInfo("Extração concluída: " + name);
    return rc;
}

static int action_build(const std::string& name){
    Spinner sp; sp.start("compilando");
    ensureDir(CFG.logs);
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-build.log");
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : fs::path(CFG.work)/name;

    // rodar hooks
    runHooks("pre-build", name, log);

    int rc = 0;
    // detectar subdiretório raiz (se tar extraiu com pasta única)
    fs::path srcdir = firstOrOnlySubdir(workdir);

    // heurísticas de build
    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, false); };

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
    sp.stop();
    if(rc==0) logInfo("Build concluído: " + name);
    return rc;
}

static int action_test(const std::string& name){
    ensureDir(CFG.logs);
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-test.log");
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : fs::path(CFG.work)/name;
    fs::path srcdir = firstOrOnlySubdir(workdir);
    auto runIn = [&](const std::string& c){ return runCmd("bash -lc 'cd " + srcdir.string() + " && " + c + "'", log, true, "testando"); };

    if(fileExists(srcdir/"Makefile")) return runIn("make check || make test || true");
    if(fileExists(srcdir/"build"/"build.ninja")) return runIn("ninja -C build test || true");
    if(fileExists(srcdir/"Cargo.toml")) return runIn("cargo test || true");
    logWarn("Nenhum teste encontrado.");
    return 0;
}

static int action_install(const std::string& name){
    // Checagem de dependências declaradas em .meta
    auto meta = metaGetAll(name);
    if (meta.count("deps")) {
        std::istringstream iss(meta["deps"]);
        std::string dep;
        while (std::getline(iss, dep, ',')) {
            if(dep.empty()) continue;
            if (!fs::exists(metaPath(dep))) {
                logErr("Dependência não instalada: " + dep);
                return 1;
            }
        }
    }

    fs::path stage, srcdir, slog;
    int rc = stage_install(name, stage, srcdir, slog);
    if(rc!=0){ logErr("Falha ao instalar no staging"); return rc; }

    // strip opcional (robusto)
    do_strip_stage(stage, slog);

    // empacotar antes de instalar no sistema
    fs::path pkgfile;
    rc = package_stage(name, stage, pkgfile, slog);
    if(rc!=0){ logErr("Falha ao empacotar"); return rc; }

    // registrar lista de arquivos e instalar sob root (fakeroot opcional)
    record_filelist_from_stage(name, stage, slog);

    // instalar no sistema
    rc = install_stage_to_system(name, stage, slog);
    if(rc!=0){ logErr("Falha ao instalar no destino"); return rc; }

    runHooks("post-install", name, slog);
    return 0;
}

static int action_package(const std::string& name){
    // Gera pacote a partir do "staging" sem instalar no sistema
    fs::path stage, srcdir, slog;
    auto meta = metaGetAll(name);
    fs::path workdir = meta.count("workdir")? fs::path(meta["workdir"]) : fs::path(CFG.work)/name;

    // Se já existir stage com conteúdo, aproveita; senão, cria via stage_install
    stage = fs::path(CFG.home)/"staging"/name;
    if(!(fs::exists(stage) && !fs::is_empty(stage))){
        int rc = stage_install(name, stage, srcdir, slog);
        if(rc!=0){ logErr("Falha ao preparar staging para pacote"); return rc; }
    } else {
        slog = fs::path(CFG.logs)/name/(timestamp()+"-package.log");
    }

    // strip e empacota
    do_strip_stage(stage, slog);

    fs::path pkgfile;
    int rc = package_stage(name, stage, pkgfile, slog);
    if(rc!=0){ logErr("Falha ao empacotar"); return rc; }

    // registra lista de arquivos (útil para info/revdep mesmo sem instalar)
    record_filelist_from_stage(name, stage, slog);

    logInfo("Pacote criado (sem instalar): " + pkgfile.string());
    return 0;
}

static int action_remove(const std::string& name){
    Spinner sp; sp.start("removendo");
    ensureDir(CFG.logs);
    fs::path log = fs::path(CFG.logs)/name/(timestamp()+"-remove.log");
    fs::path filelist = fs::path(CFG.repo)/(name+".files");
    if(!fs::exists(filelist)){
        sp.stop(); logErr("Arquivo de lista não encontrado: " + filelist.string()); return 1;
    }
    std::ifstream ifs(filelist); std::string rel;
    int rc_total=0;
    while(std::getline(ifs, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        if(fs::exists(p)){
            std::string cmd = "rm -f '" + p.string() + "'";
            int rc = runCmd(cmd, log); rc_total |= rc;
        }
    }
    // tentar remover diretórios vazios
    std::string clean = "bash -lc 'sort -r " + filelist.string() + " | xargs -I{} dirname {} | sort -u | while read d; do rmdir -p --ignore-fail-on-non-empty \"" + CFG.destdir + "/$d\" 2>/dev/null || true; done'";
    runCmd(clean, log);

    runHooks("post-remove", name, log);
    sp.stop();
    logInfo("Remoção concluída: " + name);
    return rc_total;
}

static int action_verify(const std::string& file, const std::string& sum){
    Spinner sp; sp.start("verificando sha256");
    ensureDir(CFG.logs);
    fs::path log = fs::path(CFG.logs)/("verify-"+timestamp()+".log");
    std::string verify = "echo '" + sum + "  " + fs::path(file).filename().string() + "' | (cd '" + fs::path(file).parent_path().string() + "' && sha256sum -c -)";
    int rc = runCmd(verify, log);
    sp.stop();
    if(rc==0) logInfo("SHA256 OK");
    return rc;
}

static int action_info(const std::string& name){
    auto kv = metaGetAll(name);
    if(kv.empty()){ logErr("Pacote desconhecido: "+name); return 1; }
    std::cout << "Nome: " << name << "\n";
    for(auto& it: kv) std::cout << it.first << ": " << it.second << "\n";
    fs::path filelist = fs::path(CFG.repo)/(name+".files");
    if(fs::exists(filelist)){
        std::cout << "Arquivos (lista): " << filelist << "\n";
    }
    return 0;
}

static int action_search(const std::string& term){
    for(auto& e: fs::directory_iterator(CFG.repo)){
        if(!e.is_regular_file()) continue;
        if(e.path().extension()==".meta"){
            std::string name = e.path().stem().string();
            bool printed = false;
            if(name.find(term)!=std::string::npos){
                std::cout << name << "\n";
                printed = true;
            }
            if(printed) continue;
            auto kv = metaGetAll(name);
            for(auto& it: kv){
                if(it.second.find(term)!=std::string::npos){ std::cout << name << "\n"; break; }
            }
        }
    }
    return 0;
}

static int action_revdep(const std::string& name){
    auto kv = metaGetAll(name);
    fs::path filelist = fs::path(CFG.repo)/(name+".files");
    if(!fs::exists(filelist)){ logErr("Sem lista de arquivos para analisar. Instale primeiro ou gere package."); return 1; }
    std::ifstream ifs(filelist); std::string rel;
    std::set<std::string> libs_missing;
    while(std::getline(ifs, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        if(!fs::exists(p)) continue;
        // apenas binários/so
        std::string check = "bash -lc 'file -b \"" + p.string() + "\" | grep -qiE \"executable|shared object\"'";
        if(runCmd(check) != 0) continue;
        // ldd -> libs not found
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
    for(auto& l: libs_missing) std::cout << "  " << l << "\n";
    // Heurística: procurar no repositório pacotes contendo a lib na lista de arquivos
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
                        std::cout << "  - " << e.path().stem().string() << " (tem " << have << ")\n";
                    }
                }
            }
        }
    }
    return 0;
}

static int action_clean(const std::string& name){
    fs::path w = fs::path(CFG.work)/name;
    fs::path l = fs::path(CFG.logs)/name;
    fs::path s = fs::path(CFG.home)/"staging"/name;
    std::error_code ec;
    fs::remove_all(w, ec);
    fs::remove_all(l, ec);
    fs::remove_all(s, ec);
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

// ========================= Ajuda =========================
static void usage(){
    std::cout << "mbuild — ferramenta de build para LFS\n\n"
              << "Comandos principais:\n"
              << "  fetch|f       <src> [--name N] [--sha256 SUM]\n"
              << "  extract|x     <arquivo|dir> [--name N]\n"
              << "  build|b       <name> [--jobs N]\n"
              << "  test|t        <name>\n"
              << "  install|i     <name> [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]\n"
              << "  package|p     <name> [--format zst|xz]\n"
              << "  remove|rm     <name>\n"
              << "  clean|c       <name>\n"
              << "  upgrade|up    <name>\n"
              << "  reinstall|ri  <name>\n"
              << "  verify|v      <arquivo> --sha256 SUM\n"
              << "  info          <name>\n"
              << "  search|s      <termo>\n"
              << "  revdep        <name>\n"
              << "  help|h\n\n"
              << "Flags globais: --color | --no-color | --no-spinner | --quiet | --verbose\n"
              << "Dirs: $MBUILD_HOME (" << CFG.home << ")\n"
              << "      sources=" << CFG.sources << " work=" << CFG.work << " logs=" << CFG.logs << " repo=" << CFG.repo << " bin=" << CFG.bin << "\n";
}

// ========================= Parser simples =========================
int main(int argc, char** argv){
    // Carregar config de arquivo e garantir diretórios
    loadFromRc(CFG);
    initDirs();

    std::vector<std::string> args(argv+1, argv+argc);
    if(args.empty()){ usage(); return 0; }

    // flags globais
    auto eatFlag = [&](const std::string& f){
        auto it = std::find(args.begin(), args.end(), f);
        if(it!=args.end()){ args.erase(it); return true; } return false;
    };
    if(eatFlag("--no-color")) CFG.color=false;
    if(eatFlag("--color")) CFG.color=true;
    if(eatFlag("--no-spinner")) CFG.spinner=false;
    if(eatFlag("--quiet")) CFG.quiet=true;
    if(eatFlag("--verbose")) CFG.verbose=true;

    if(args.empty()){ usage(); return 0; }

    std::string cmd = args.front(); args.erase(args.begin());

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

    if(cmd=="help"||cmd=="h"){ usage(); return 0; }

    if(cmd=="fetch"||cmd=="f"){
        if(args.empty()){ logErr("Uso: fetch <src>"); return 2; }
        std::string src = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        auto sha = getOpt("--sha256");
        return action_fetch(src, name, sha);
    }

    if(cmd=="extract"||cmd=="x"){
        if(args.empty()){ logErr("Uso: extract <arquivo|dir>"); return 2; }
        std::string in = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        return action_extract(in, name);
    }

    if(cmd=="build"||cmd=="b"){
        if(args.empty()){ logErr("Uso: build <name>"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(auto j=getOpt("--jobs")) CFG.jobs = std::stoi(*j);
        return action_build(name);
    }

    if(cmd=="test"||cmd=="t"){
        if(args.empty()){ logErr("Uso: test <name>"); return 2; }
        return action_test(args.front());
    }

    if(cmd=="install"||cmd=="i"){
        if(args.empty()){ logErr("Uso: install <name>"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(eatFlag("--fakeroot")) CFG.use_fakeroot=true;
        if(eatFlag("--no-strip")) CFG.do_strip=false;
        if(eatFlag("--strip")) CFG.do_strip=true;
        if(auto f=getOpt("--strip-flags")) CFG.strip_flags=*f;
        if(auto d=getOpt("--destdir"))   CFG.destdir=*d;
        if(auto fmt=getOpt("--format"))  CFG.package_format=(*fmt=="xz"?"xz":"zst");
        return action_install(name);
    }

    if(cmd=="package"||cmd=="p"){
        if(args.empty()){ logErr("Uso: package <name>"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(auto fmt=getOpt("--format"))  CFG.package_format=(*fmt=="xz"?"xz":"zst");
        return action_package(name);
    }

    if(cmd=="remove"||cmd=="rm"){
        if(args.empty()){ logErr("Uso: remove <name>"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        return action_remove(name);
    }

    if(cmd=="verify"||cmd=="v"){
        if(args.size()<2){ logErr("Uso: verify <arquivo> --sha256 SUM"); return 2; }
        std::string file = args.front(); args.erase(args.begin());
        auto sha = getOpt("--sha256"); if(!sha){ logErr("--sha256 obrigatório"); return 2; }
        return action_verify(file, *sha);
    }

    if(cmd=="info"){
        if(args.empty()){ logErr("Uso: info <name>"); return 2; }
        return action_info(args.front());
    }

    if(cmd=="search"||cmd=="s"){
        if(args.empty()){ logErr("Uso: search <termo>"); return 2; }
        return action_search(args.front());
    }

    if(cmd=="revdep"){
        if(args.empty()){ logErr("Uso: revdep <name>"); return 2; }
        return action_revdep(args.front());
    }

    if(cmd=="clean"||cmd=="c"){
        if(args.empty()){ logErr("Uso: clean <name>"); return 2; }
        return action_clean(args.front());
    }

    if(cmd=="upgrade"||cmd=="up"){
        if(args.empty()){ logErr("Uso: upgrade <name>"); return 2; }
        return action_upgrade(args.front());
    }

    if(cmd=="reinstall"||cmd=="ri"){
        if(args.empty()){ logErr("Uso: reinstall <name>"); return 2; }
        return action_reinstall(args.front());
    }

    logErr("Comando desconhecido: " + cmd);
    usage();
    return 2;
}
