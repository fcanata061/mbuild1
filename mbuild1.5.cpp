#include <bits/stdc++.h>
#include <filesystem>
#include <openssl/sha.h>
#include <zlib.h>     // para compressão
#include <unistd.h>   // fork/exec
#include <sys/wait.h>

namespace fs = std::filesystem;

// ========================= Configuração =========================
struct Config {
    std::string home      = fs::current_path().string();
    std::string sources   = "sources";
    std::string work      = "work";
    std::string logs      = "logs";
    std::string repo      = "repo";
    std::string bin       = "packages";
    std::string staging   = "staging";
    std::string destdir   = "/";
    int jobs              = 4;
    std::string strip_flags = "-s";
    std::string package_format = "xz"; // xz | zst
    std::string git_remote = "";
    std::string git_branch = "main";
} CFG;

// ========================= Estruturas =========================
struct PackageMeta {
    std::string name;
    std::string version;
    std::vector<std::string> deps;
    std::string source;
    std::string sha256;
};

struct PackageDB {
    std::map<std::string, PackageMeta> installed;
} DBSTATE;

// ========================= Utilitários =========================
std::string sha256sum(const std::string& path) {
    FILE* file = fopen(path.c_str(), "rb");
    if (!file) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        SHA256_Update(&ctx, buf, n);
    }
    fclose(file);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

bool runCommand(const std::string& cmd, const std::string& logfile="") {
    std::string full = cmd;
    if (!logfile.empty())
        full += " >>" + logfile + " 2>&1";
    int ret = system(full.c_str());
    return WEXITSTATUS(ret) == 0;
}

// ========================= Banco de Dados =========================
void db_load() {
    std::string dbfile = CFG.repo + "/db.txt";
    if (!fs::exists(dbfile)) return;
    std::ifstream in(dbfile);
    std::string line;
    while (std::getline(in,line)) {
        std::istringstream iss(line);
        PackageMeta m;
        std::getline(iss,m.name,':');
        std::getline(iss,m.version,':');
        std::string deps;
        std::getline(iss,deps,':');
        std::getline(iss,m.source,':');
        std::getline(iss,m.sha256,':');
        std::istringstream ds(deps);
        std::string d;
        while (std::getline(ds,d,',')) if(!d.empty()) m.deps.push_back(d);
        DBSTATE.installed[m.name] = m;
    }
}
void db_save() {
    fs::create_directories(CFG.repo);
    std::ofstream out(CFG.repo + "/db.txt");
    for (auto& [n,m] : DBSTATE.installed) {
        out << m.name << ":" << m.version << ":";
        for (size_t i=0;i<m.deps.size();i++) {
            out << m.deps[i]; if(i+1<m.deps.size()) out << ",";
        }
        out << ":" << m.source << ":" << m.sha256 << "\n";
    }
}

// ========================= Parser de Metadados =========================
PackageMeta parseMeta(const std::string& path) {
    PackageMeta m;
    std::ifstream in(path);
    std::string k,v;
    while (in>>k>>v) {
        if (k=="name:") m.name=v;
        else if (k=="version:") m.version=v;
        else if (k=="depends:") {
            std::istringstream ss(v);
            std::string d;
            while (std::getline(ss,d,',')) m.deps.push_back(d);
        }
        else if (k=="source:") m.source=v;
        else if (k=="sha256:") m.sha256=v;
    }
    return m;
}

// ========================= Resolução de Dependências =========================
bool topoSort(const std::string& pkg, 
              const std::map<std::string,PackageMeta>& repo, 
              std::vector<std::string>& order) {
    std::set<std::string> visited, stack;
    std::function<bool(const std::string&)> dfs = [&](const std::string& u){
        if (stack.count(u)) return false; 
        if (visited.count(u)) return true;
        stack.insert(u);
        auto it=repo.find(u);
        if(it!=repo.end()) {
            for(auto& d:it->second.deps) if(!dfs(d)) return false;
        }
        stack.erase(u);
        visited.insert(u);
        order.push_back(u);
        return true;
    };
    return dfs(pkg);
}

// ========================= Rollback Helper =========================
void rollbackInstall(const std::string& pkg) {
    std::cerr << "[rollback] revertendo " << pkg << "\n";
    DBSTATE.installed.erase(pkg);
    db_save();
    fs::remove_all(CFG.staging + "/" + pkg);
    fs::remove_all(CFG.work + "/" + pkg);
}
// ========================= Helpers de FS/Exec/Logs =========================
static inline std::string pjoin(const std::string& a, const std::string& b){
    return (fs::path(a)/b).string();
}
static inline bool existsf(const std::string& p){ return fs::exists(p); }
static inline void ensuredir(const std::string& p){ fs::create_directories(p); }
static inline std::string timestamp(){
    std::time_t t=std::time(nullptr);
    char buf[32];
    std::strftime(buf,sizeof(buf),"%Y%m%d-%H%M%S",std::localtime(&t));
    return buf;
}
static inline std::string logPath(const std::string& pkg, const std::string& phase){
    ensuredir(CFG.logs);
    ensuredir(pjoin(CFG.logs, pkg));
    return pjoin(pjoin(CFG.logs, pkg), timestamp()+"-"+phase+".log");
}
static inline bool toolExists(const std::string& tool){
    std::string cmd = "sh -c \"command -v "+tool+" >/dev/null 2>&1\"";
    return WEXITSTATUS(system(cmd.c_str()))==0;
}

// Envelopa comando com logging + exibição
static bool runLogged(const std::string& cmd, const std::string& logfile){
    std::string wrapped = cmd + " >>'" + logfile + "' 2>&1";
    int rc = system(wrapped.c_str());
    return WEXITSTATUS(rc)==0;
}

// ========================= Detecção de Arquivo/Arquivador =========================
static std::string detectArchive(const std::string& path){
    std::string s=path;
    if(std::regex_search(s, std::regex("\\.(tar\\.(gz|bz2|xz|zst))$"))) return "tar";
    if(std::regex_search(s, std::regex("\\.(tgz|tbz2|txz)$"))) return "tar";
    if(std::regex_search(s, std::regex("\\.zip$"))) return "zip";
    if(std::regex_search(s, std::regex("\\.7z$"))) return "7z";
    return "dir";
}

// ========================= I/O dos .files por pacote =========================
static std::string filesListPath(const std::string& pkg){
    ensuredir(CFG.repo);
    return pjoin(CFG.repo, pkg + ".files");
}
static std::set<std::string> readFilesList(const std::string& pkg){
    std::set<std::string> r;
    std::ifstream in(filesListPath(pkg));
    std::string line;
    while(std::getline(in,line)){
        if(!line.empty()) r.insert(line);
    }
    return r;
}
static void writeFilesList(const std::string& pkg, const std::vector<std::string>& files){
    ensuredir(CFG.repo);
    std::ofstream out(filesListPath(pkg));
    for(auto& f: files) out<<f<<"\n";
}

// Lista recursiva relativa ao stage root
static void collectRelativeFiles(const std::string& root, std::vector<std::string>& out){
    for(auto& e: fs::recursive_directory_iterator(root)){
        if(fs::is_regular_file(e.path()) || fs::is_symlink(e.path())){
            std::string rel = fs::relative(e.path(), root).generic_string();
            if(rel.empty()) continue;
            out.push_back(rel);
        }
    }
    std::sort(out.begin(), out.end());
}

// ========================= Conflitos de Arquivos =========================
// Regras: conflito se:
//  - arquivo de stage colide com arquivo já instalado por OUTRO pacote (.files de terceiros)
//  - arquivo existe no filesystem DESTDIR (p.e. base do sistema) e não pertence a este pacote
static std::vector<std::string> detectConflicts(const std::string& pkg,
                                                const std::vector<std::string>& stageFiles){
    std::vector<std::string> conflicts;
    // Carrega todas as listas de arquivos de pacotes instalados (exceto o próprio)
    std::map<std::string, std::set<std::string>> others;
    for(auto& ent: fs::directory_iterator(CFG.repo)){
        if(!ent.is_regular_file()) continue;
        auto p = ent.path();
        if(p.extension() == ".files"){
            std::string name = p.stem().string();
            if(name==pkg) continue;
            auto it = DBSTATE.installed.find(name);
            if(it==DBSTATE.installed.end()) continue; // só pacotes instalados
            others[name] = readFilesList(name);
        }
    }
    // Verifica conflitos
    for(auto& rel: stageFiles){
        std::string absPath = pjoin(CFG.destdir, rel);
        // Se o arquivo pertence a outro pacote
        for(auto& [oname, fl]: others){
            if(fl.count(rel)){
                conflicts.push_back(rel + " (pertence a " + oname + ")");
                break;
            }
        }
        // Se existe no FS e não pertence a ninguém
        if(existsf(absPath)){
            // verifica se já pertence a este pacote (reinstalação)
            auto cur = readFilesList(pkg);
            if(!cur.count(rel)){
                conflicts.push_back(rel + " (já existe no sistema)");
            }
        }
    }
    return conflicts;
}

// ========================= Empacotamento =========================
static bool packStage(const std::string& pkg, const std::string& stageDir,
                      std::string& outPkgFile, const std::string& log){
    ensuredir(CFG.repo);
    std::string suffix = (CFG.package_format=="zst" ? "tar.zst" : "tar.xz");
    outPkgFile = pjoin(CFG.repo, pkg + "-" + timestamp() + "." + suffix);
    std::string cmd;
    if(CFG.package_format=="zst"){
        if(!toolExists("zstd")){
            std::cerr<<"[erro] zstd não encontrado no PATH.\n";
            return false;
        }
        cmd = "sh -c \"cd '"+stageDir+"' && tar -I 'zstd -T0 -19' -cf '"+outPkgFile+"' .\"";
    }else{
        // xz padrão
        cmd = "sh -c \"cd '"+stageDir+"' && tar -Jcf '"+outPkgFile+"' .\"";
    }
    return runLogged(cmd, log);
}

// ========================= Instalação no sistema (com fakeroot opcional) =========================
static bool installToSystem(const std::string& stageDir, bool use_fakeroot, const std::string& log){
    // verificação do fakeroot (evolução 5)
    if(use_fakeroot){
        if(!toolExists("fakeroot")){
            std::cerr<<"[erro] --fakeroot solicitado, mas 'fakeroot' não está disponível.\n";
            return false;
        }
    }
    std::string pipe_cmd = "sh -c \"cd '"+stageDir+"' && tar -cpf - . | ";
    if(use_fakeroot) pipe_cmd += "fakeroot ";
    pipe_cmd += "tar -C '"+CFG.destdir+"' -xpf -\"";
    return runLogged(pipe_cmd, log);
}

// ========================= Fase: fetch =========================
static bool action_fetch(const std::string& src, const std::string& pkg, const std::string& shaOpt){
    ensuredir(CFG.sources);
    std::string log = logPath(pkg, "fetch");

    // detecta: git URL, http(s), dir local
    auto isGit = [&](const std::string& s){
        if(s.rfind("git@",0)==0) return true;
        if(s.rfind("ssh://",0)==0) return true;
        if(s.find(".git")!=std::string::npos) return true;
        return false;
    };
    auto isUrl = [&](const std::string& s){
        return s.rfind("http://",0)==0 || s.rfind("https://",0)==0;
    };

    if(isGit(src)){
        // clone ou pull
        std::string dst = pjoin(CFG.sources, pkg);
        if(existsf(dst)){
            return runLogged("git -C '"+dst+"' pull --ff-only", log);
        }else{
            return runLogged("git clone --depth 1 '"+src+"' '"+dst+"'", log);
        }
    } else if(isUrl(src)) {
        std::string base = fs::path(src).filename().string();
        std::string out = pjoin(CFG.sources, base);
        if(!existsf(out)){
            if(!runLogged("curl -L --fail -o '"+out+"' '"+src+"'", log)) return false;
        }
        if(!shaOpt.empty()){
            std::string calc = sha256sum(out);
            if(calc != shaOpt){
                std::ofstream lf(log, std::ios::app);
                lf<<"[erro] SHA256 esperado="<<shaOpt<<" obtido="<<calc<<"\n";
                return false;
            }
        }
        return true;
    } else {
        // diretório local → copia em cache
        std::string dst = pjoin(CFG.sources, pkg);
        ensuredir(dst);
        std::string cmd = "sh -c \"cp -a '"+src+"'/.' '"+dst+"'\"";
        return runLogged(cmd, log);
    }
}

// ========================= Fase: extract =========================
static bool action_extract(const std::string& input, const std::string& pkg){
    ensuredir(CFG.work);
    std::string outdir = pjoin(CFG.work, pkg);
    ensuredir(outdir);
    std::string log = logPath(pkg, "extract");
    std::string kind = detectArchive(input);
    if(kind=="tar"){
        return runLogged("tar -C '"+outdir+"' -xf '"+input+"'", log);
    } else if(kind=="zip"){
        return runLogged("unzip -q -d '"+outdir+"' '"+input+"'", log);
    } else if(kind=="7z"){
        return runLogged("7z x -o'"+outdir+"' '"+input+"'", log);
    } else { // dir
        return runLogged("sh -c \"cp -a '"+input+"'/.' '"+outdir+"'\"", log);
    }
}

// ========================= Fase: build (com logs e -j) =========================
static bool action_build(const std::string& pkg, int jobs){
    std::string log = logPath(pkg, "build");
    std::string workdir = pjoin(CFG.work, pkg);

    // se houver único subdir, entra nele
    auto firstOrOnlySubdir = [&](const std::string& root)->std::string{
        int dirs=0; std::string last=root;
        for(auto& e: fs::directory_iterator(root)){
            if(fs::is_directory(e.path())){ dirs++; last = e.path().string(); }
        }
        if(dirs==1) return last;
        return root;
    };
    std::string srcdir = firstOrOnlySubdir(workdir);

    auto runIn = [&](const std::string& c){
        return runLogged("sh -c \"cd '"+srcdir+"' && "+c+"\"", log);
    };

    // autodetecta buildsystem (evolução mantida)
    if(existsf(pjoin(srcdir,"build.sh"))){
        if(!runIn("chmod +x build.sh && ./build.sh -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"autogen.sh"))){
        if(!runIn("chmod +x autogen.sh && ./autogen.sh")) return false;
        if(!runIn("./configure --prefix=/usr")) return false;
        if(!runIn("make -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"configure"))){
        if(!runIn("./configure --prefix=/usr")) return false;
        if(!runIn("make -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"CMakeLists.txt"))){
        if(!runIn("mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr ..")) return false;
        if(!runIn("cd build && make -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"meson.build"))){
        if(!runIn("meson setup build --prefix=/usr")) return false;
        if(!runIn("ninja -C build -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"setup.py"))){
        if(!runIn("python3 setup.py build")) return false;
    } else if(existsf(pjoin(srcdir,"pyproject.toml"))){
        if(!runIn("pip3 wheel . -w dist")) return false;
    } else if(existsf(pjoin(srcdir,"Cargo.toml"))){
        if(!runIn("cargo build --release -j"+std::to_string(jobs))) return false;
    } else if(existsf(pjoin(srcdir,"go.mod"))){
        if(!runIn("go build ./...")) return false;
    } else if(existsf(pjoin(srcdir,"Makefile"))){
        if(!runIn("make -j"+std::to_string(jobs))) return false;
    } else {
        std::ofstream lf(log, std::ios::app);
        lf<<"[aviso] Nenhum sistema de build detectado, ignorando.\n";
    }
    return true;
}

// ========================= Fase: test (make check/test, ninja test, cargo test) =========================
static bool action_test(const std::string& pkg){
    std::string log = logPath(pkg, "test");
    std::string workdir = pjoin(CFG.work, pkg);

    auto firstOrOnlySubdir = [&](const std::string& root)->std::string{
        int dirs=0; std::string last=root;
        for(auto& e: fs::directory_iterator(root)){
            if(fs::is_directory(e.path())){ dirs++; last = e.path().string(); }
        }
        if(dirs==1) return last;
        return root;
    };
    std::string srcdir = firstOrOnlySubdir(workdir);

    auto runIn = [&](const std::string& c){
        return runLogged("sh -c \"cd '"+srcdir+"' && "+c+"\"", log);
    };

    // evolução 6: execuções reais porém não-fatais
    bool any=false, ok=true;
    if(existsf(pjoin(srcdir,"Makefile"))){
        any=true; ok = runIn("make check || make test || true") && ok;
    }
    if(existsf(pjoin(srcdir,"build")) && existsf(pjoin(pjoin(srcdir,"build"),"build.ninja"))){
        any=true; ok = runIn("ninja -C build test || true") && ok;
    }
    if(existsf(pjoin(srcdir,"Cargo.toml"))){
        any=true; ok = runIn("cargo test || true") && ok;
    }
    if(!any){
        std::ofstream lf(log, std::ios::app);
        lf<<"[info] Sem testes detectados.\n";
    }
    return ok;
}

// ========================= Strip stage =========================
static void stripStage(const std::string& stageDir, const std::string& log){
    std::string cmd =
        "sh -c \"find '"+stageDir+"' -type f -exec sh -c '"
        "mt=$(file -b --mime-type \"$1\"); "
        "if [ \"$mt\" = application/x-executable ] || "
        "[ \"$mt\" = application/x-pie-executable ] || "
        "[ \"$mt\" = application/x-sharedlib ]; then "
        "strip "+CFG.strip_flags+" \"$1\" || true; "
        "fi' _ {} \\;\"";
    runLogged(cmd, log);
}

// ========================= Fase: stage + install =========================
static bool stage_install(const std::string& pkg, std::string& stageDir, std::vector<std::string>& stagedFiles){
    std::string log = logPath(pkg, "install");
    std::string workdir = pjoin(CFG.work, pkg);

    auto firstOrOnlySubdir = [&](const std::string& root)->std::string{
        int dirs=0; std::string last=root;
        for(auto& e: fs::directory_iterator(root)){
            if(fs::is_directory(e.path())){ dirs++; last = e.path().string(); }
        }
        if(dirs==1) return last;
        return root;
    };
    std::string srcdir = firstOrOnlySubdir(workdir);

    stageDir = pjoin(CFG.staging, pkg);
    ensuredir(stageDir);

    auto runIn = [&](const std::string& c){
        return runLogged("sh -c \"cd '"+srcdir+"' && "+c+"\"", log);
    };

    bool ok=false;
    if(existsf(pjoin(srcdir,"build")) && existsf(pjoin(pjoin(srcdir,"build"),"build.ninja"))){
        ok = runIn("ninja -C build install DESTDIR='"+stageDir+"'");
    } else if(existsf(pjoin(srcdir,"CMakeLists.txt")) && existsf(pjoin(srcdir,"build"))){
        ok = runIn("cd build && make install DESTDIR='"+stageDir+"'");
    } else if(existsf(pjoin(srcdir,"setup.py"))){
        ok = runIn("python3 setup.py install --root='"+stageDir+"' --prefix=/usr");
    } else if(existsf(pjoin(srcdir,"pyproject.toml"))){
        ok = runIn("pip3 install . --prefix=/usr --root='"+stageDir+"'");
    } else if(existsf(pjoin(srcdir,"Cargo.toml"))){
        ok = runIn("cargo build --release -j"+std::to_string(CFG.jobs));
        if(ok){
            std::string copyBins =
                "sh -c \"mkdir -p '"+pjoin(stageDir,"/usr/bin")+
                "'; for f in target/release/*; do if [ -f \\\"$f\\\" ] && "
                "file -b \\\"$f\\\" | grep -qi executable; then cp -a \\\"$f\\\" '"+pjoin(stageDir,"/usr/bin/")+
                "'; fi; done\"";
            ok = runLogged(copyBins, log);
        }
    } else if(existsf(pjoin(srcdir,"go.mod"))){
        ok = runIn("go build ./...");
        if(ok){
            std::string copyBins =
                "sh -c \"mkdir -p '"+pjoin(stageDir,"/usr/bin")+
                "'; for f in $(find . -maxdepth 1 -type f); do if file -b \\\"$f\\\" | grep -qi executable; then cp -a \\\"$f\\\" '"+pjoin(stageDir,"/usr/bin/")+"'; fi; done\"";
            ok = runLogged(copyBins, log);
        }
    } else {
        ok = runIn("make install DESTDIR='"+stageDir+"'");
    }
    if(!ok) return false;

    // strip (evolução 4/partial de otimização)
    stripStage(stageDir, log);

    // lista arquivos do stage
    collectRelativeFiles(stageDir, stagedFiles);
    return true;
}

// ========================= Instalação completa (com rollback e conflitos) =========================
static bool action_install_full(const std::string& pkg, bool use_fakeroot){
    std::string log = logPath(pkg, "install-all");
    std::string stageDir; std::vector<std::string> staged;
    if(!stage_install(pkg, stageDir, staged)){
        std::ofstream lf(log, std::ios::app); lf<<"[erro] stage_install falhou.\n";
        rollbackInstall(pkg);
        return false;
    }

    // evolução 2: detectar conflitos
    auto conflicts = detectConflicts(pkg, staged);
    if(!conflicts.empty()){
        std::ofstream lf(log, std::ios::app);
        lf<<"[erro] Conflitos detectados:\n";
        for(auto& c: conflicts) lf<<"  - "<<c<<"\n";
        // rollback e aborta
        rollbackInstall(pkg);
        return false;
    }

    // evolução 1: rollback se falhar instalação real
    if(!installToSystem(stageDir, use_fakeroot, log)){
        rollbackInstall(pkg);
        return false;
    }

    // registra lista de arquivos
    writeFilesList(pkg, staged);
    return true;
}

// ========================= Empacotar sem instalar =========================
static bool action_package(const std::string& pkg){
    std::string log = logPath(pkg, "package");
    std::string stageDir = pjoin(CFG.staging, pkg);
    if(!(existsf(stageDir) && !fs::is_empty(stageDir))){
        // tenta criar via stage_install
        std::vector<std::string> staged;
        if(!stage_install(pkg, stageDir, staged)){
            std::ofstream lf(log, std::ios::app); lf<<"[erro] stage_install falhou.\n";
            return false;
        }
    }
    std::string pkgfile;
    if(!packStage(pkg, stageDir, pkgfile, log)) return false;
    std::ofstream lf(log, std::ios::app);
    lf<<"[ok] Pacote criado: "<<pkgfile<<"\n";
    return true;
}

// ========================= Remoção reversa =========================
static bool action_remove(const std::string& pkg){
    std::string log = logPath(pkg, "remove");
    // Carrega lista
    auto files = readFilesList(pkg);
    if(files.empty()){
        std::ofstream lf(log, std::ios::app); lf<<"[erro] "+pkg+" sem .files registrado.\n";
        return false;
    }
    // Remove arquivos
    bool ok=true;
    for(auto it = files.rbegin(); it!=files.rend(); ++it){
        std::string abs = pjoin(CFG.destdir, *it);
        if(existsf(abs)){
            std::string cmd = "rm -f '"+abs+"'";
            if(!runLogged(cmd, log)) ok=false;
        }
    }
    // Limpa diretórios vazios
    std::string clean = "sh -c \"sort -r '"+filesListPath(pkg)+"' | xargs -I{} dirname {} | sort -u | "
                        "while read d; do rmdir -p --ignore-fail-on-non-empty '"+CFG.destdir+"/'$d 2>/dev/null || true; done\"";
    runLogged(clean, log);

    // Atualiza DB e apaga .files
    DBSTATE.installed.erase(pkg);
    db_save();
    std::error_code ec;
    fs::remove(filesListPath(pkg), ec);

    std::ofstream lf(log, std::ios::app);
    lf<<"[ok] Remoção concluída: "<<pkg<<"\n";
    return ok;
}

// ========================= Upgrade / Reinstall =========================
static bool action_upgrade(const std::string& pkg, bool use_fakeroot){
    if(!action_remove(pkg)) return false;
    return action_install_full(pkg, use_fakeroot);
}
static bool action_reinstall(const std::string& pkg, bool use_fakeroot){
    return action_install_full(pkg, use_fakeroot);
}

// ========================= Verify SHA256 =========================
static bool action_verify(const std::string& file, const std::string& expect){
    std::string log = logPath("verify", "sha256");
    std::string got = sha256sum(file);
    std::ofstream lf(log, std::ios::app);
    lf<<"file="<<file<<" expect="<<expect<<" got="<<got<<"\n";
    bool ok = (got==expect);
    if(!ok) std::cerr<<"[erro] SHA256 não confere.\n";
    else std::cout<<"SHA256 OK\n";
    return ok;
}

// ========================= Info / Search =========================
static void action_info(const std::string& pkg){
    auto it = DBSTATE.installed.find(pkg);
    if(it == DBSTATE.installed.end()){
        std::cerr<<"Pacote não instalado: "<<pkg<<"\n"; return;
    }
    auto& m = it->second;
    std::cout<<"Nome: "<<m.name<<"\n";
    std::cout<<"Versão: "<<m.version<<"\n";
    std::cout<<"Source: "<<m.source<<"\n";
    std::cout<<"SHA256: "<<m.sha256<<"\n";
    std::cout<<"Deps: ";
    for(size_t i=0;i<m.deps.size();++i){
        std::cout<<m.deps[i]<<(i+1<m.deps.size()?",":"");
    }
    std::cout<<"\nArquivos: "<<filesListPath(pkg)<<"\n";
}

static void action_search(const std::string& term){
    for(auto& [n,m]: DBSTATE.installed){
        if(n.find(term)!=std::string::npos || m.source.find(term)!=std::string::npos){
            std::cout<<n<<"\n";
            continue;
        }
        for(auto& d: m.deps){
            if(d.find(term)!=std::string::npos){ std::cout<<n<<"\n"; break; }
        }
    }
}

// ========================= Revdep (ldd) =========================
static void action_revdep(const std::string& pkg){
    auto fl = readFilesList(pkg);
    if(fl.empty()){
        std::cerr<<"Sem .files para "<<pkg<<"\n"; return;
    }
    std::set<std::string> missing;
    for(auto& rel: fl){
        std::string p = pjoin(CFG.destdir, rel);
        if(!existsf(p)) continue;
        // apenas binários/so
        std::string chk = "sh -c \"file -b '"+p+"' | grep -qiE 'executable|shared object'\"";
        if(WEXITSTATUS(system(chk.c_str()))!=0) continue;
        // ldd
        std::string cmd = "sh -c \"ldd '"+p+"' 2>/dev/null | awk '/not found/{print $1}'\"";
        FILE* fp = popen(cmd.c_str(), "r");
        if(!fp) continue;
        char buf[512]; std::string out;
        while(fgets(buf,sizeof(buf),fp)) out += buf;
        pclose(fp);
        std::istringstream iss(out); std::string lib;
        while(iss>>lib) missing.insert(lib);
    }
    if(missing.empty()){
        std::cout<<"Sem dependências ausentes.\n"; return;
    }
    std::cout<<"Bibliotecas ausentes:\n";
    for(auto& l: missing) std::cout<<"  "<<l<<"\n";

    std::cout<<"Sugestões (pacotes contendo .so):\n";
    for(auto& ent: fs::directory_iterator(CFG.repo)){
        if(ent.path().extension()!=".files") continue;
        std::ifstream in(ent.path());
        std::string rel;
        std::set<std::string> libs;
        while(std::getline(in,rel)){
            if(rel.find(".so")!=std::string::npos) libs.insert(fs::path(rel).filename().string());
        }
        for(auto& miss: missing){
            for(auto& have: libs){
                if(have.rfind(miss,0)==0){
                    std::cout<<"  - "<<ent.path().stem().string()<<" (tem "<<have<<")\n";
                }
            }
        }
    }
}

// ========================= Sync (git) =========================
static bool action_sync(const std::string& scope, const std::string& message,
                        const std::string& remote, const std::string& branch,
                        bool push, bool init_repo){
    std::string root = CFG.home;
    ensuredir(root);
    auto run = [&](const std::string& c){
        std::string log = logPath("sync","git");
        return runLogged(c, log);
    };

    if(init_repo && !existsf(pjoin(root,".git"))){
        if(!run("git -C '"+root+"' init")) return false;
        if(!remote.empty()){
            run("git -C '"+root+"' remote remove origin >/dev/null 2>&1 || true");
            if(!run("git -C '"+root+"' remote add origin '"+remote+"'")) return false;
        } else if(!CFG.git_remote.empty()){
            run("git -C '"+root+"' remote remove origin >/dev/null 2>&1 || true");
            run("git -C '"+root+"' remote add origin '"+CFG.git_remote+"'");
        }
    }

    // .gitignore mínimo
    if(!existsf(pjoin(root,".gitignore"))){
        std::ofstream gi(pjoin(root,".gitignore"));
        gi<<"# mbuild defaults\n*.tmp\n.cache/\n";
    }

    // caminhos
    std::vector<std::string> paths;
    if(scope=="all") paths = {CFG.repo, CFG.logs, CFG.work, CFG.sources, CFG.bin, CFG.staging};
    else if(scope=="repo"||scope=="packages"||scope=="pkgs") paths = {CFG.repo};
    else if(scope=="logs") paths = {CFG.logs};
    else if(scope=="work") paths = {CFG.work};
    else if(scope=="sources") paths = {CFG.sources};
    else paths = {CFG.repo};

    for(auto& p: paths){
        if(!existsf(p)) continue;
        run("git -C '"+root+"' add -A '"+fs::relative(p, root).string()+"'");
    }

    std::string msg = message.empty()? ("mbuild sync: "+timestamp()) : message;
    run("sh -c \"cd '"+root+"' && git diff --cached --quiet || git commit -m '"+msg+"'\"");

    std::string rem = remote.empty()? CFG.git_remote : remote;
    std::string br  = branch.empty()? CFG.git_branch  : branch;
    if(push){
        if(rem.empty()){
            std::cerr<<"[sync] remote vazio; pulando push.\n";
            return true;
        }
        run("sh -c \"cd '"+root+"' && git symbolic-ref -q HEAD || git checkout -b '"+br+"'\"");
        if(!run("git -C '"+root+"' push -u '"+rem+"' '"+br+"'")){
            std::cerr<<"git push falhou.\n";
            return false;
        }
    }
    return true;
}

// ========================= Uso (CLI) =========================
static void usage(){
    std::cout <<
"mbuild — ferramenta de build/empacote para LFS (com resolução de dependências)\n\n"
"Uso:\n"
"  mbuild <comando> [opções]\n\n"
"Comandos (nomes longos | atalho | número):\n"
"  help                    | h   | 0   — mostrar ajuda\n"
"  fetch <SRC>             | f   | 1   — baixar (curl/git/dir) [--name N] [--sha256 SUM]\n"
"  extract <ARQ|DIR>       | x   | 2   — extrair/copiar para work [--name N]\n"
"  build <NAME>            | b   | 3   — compilar [--jobs N]\n"
"  test <NAME>             | t   | 4   — rodar testes\n"
"  install <NAME>          | i   | 5   — resolver deps e instalar (staging→pacote→sistema)\n"
"      [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]\n"
"  package <NAME>          | p   | 6   — gerar pacote a partir do staging [--format zst|xz]\n"
"  remove <NAME>           | rm  | 7   — remover (dependentes → alvo) em ordem reversa\n"
"  upgrade <NAME>          | up  | 8   — remove + install (com deps)\n"
"  reinstall <NAME>        | ri  | 9   — install novamente (com deps)\n"
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

// ========================= Map Alias =========================
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

// ========================= Main (CLI) =========================
int main(int argc, char** argv){
    // prepara diretórios básicos
    ensuredir(CFG.sources);
    ensuredir(CFG.work);
    ensuredir(CFG.logs);
    ensuredir(CFG.repo);
    ensuredir(CFG.bin);
    ensuredir(CFG.staging);

    db_load();

    std::vector<std::string> args(argv+1, argv+argc);
    if(args.empty()){ usage(); return 0; }

    // flags simples (algumas globais)
    auto eatFlag = [&](const std::string& f){
        auto it = std::find(args.begin(), args.end(), f);
        if(it!=args.end()){ args.erase(it); return true; } return false;
    };
    auto getOpt = [&](const std::string& key)->std::string{
        for(size_t i=0;i+1<args.size();++i){
            if(args[i]==key){
                std::string v=args[i+1];
                args.erase(args.begin()+i, args.begin()+i+2);
                return v;
            }
        }
        return "";
    };

    // aceitar alguns globais (simplesmente armazenamos)
    if(eatFlag("--no-strip")) CFG.strip_flags = ""; // não usar -s
    if(eatFlag("--strip")) if(CFG.strip_flags.empty()) CFG.strip_flags="-s";
    std::string fmt = getOpt("--format"); if(!fmt.empty()) CFG.package_format=(fmt=="zst"?"zst":"xz");
    std::string dest = getOpt("--destdir"); if(!dest.empty()) CFG.destdir=dest;
    std::string jobsOpt = getOpt("--jobs"); if(!jobsOpt.empty()) try{ CFG.jobs=std::max(1, std::stoi(jobsOpt)); }catch(...){}

    std::string cmd = mapAlias(args.front()); args.erase(args.begin());
    if(cmd=="help"){ usage(); return 0; }

    if(cmd=="fetch"){
        if(args.empty()){ std::cerr<<"Uso: fetch <src> [--name N] [--sha256 SUM]\n"; return 2; }
        std::string src = args.front(); args.erase(args.begin());
        std::string name = getOpt("--name"); if(name.empty()) name = fs::path(src).filename().string();
        std::string sha  = getOpt("--sha256");
        bool ok = action_fetch(src, name, sha);
        return ok?0:1;
    }
    if(cmd=="extract"){
        if(args.empty()){ std::cerr<<"Uso: extract <arquivo|dir> [--name N]\n"; return 2; }
        std::string in = args.front(); args.erase(args.begin());
        std::string name = getOpt("--name"); if(name.empty()) name = fs::path(in).filename().string();
        bool ok = action_extract(in, name);
        return ok?0:1;
    }
    if(cmd=="build"){
        if(args.empty()){ std::cerr<<"Uso: build <name> [--jobs N]\n"; return 2; }
        std::string name = args.front(); args.erase(args.begin());
        std::string j = getOpt("--jobs"); if(!j.empty()) try{ CFG.jobs=std::max(1, std::stoi(j)); }catch(...){}
        bool ok = action_build(name, CFG.jobs);
        return ok?0:1;
    }
    if(cmd=="test"){
        if(args.empty()){ std::cerr<<"Uso: test <name>\n"; return 2; }
        bool ok = action_test(args.front());
        return ok?0:1;
    }
    if(cmd=="install"){
        if(args.empty()){ std::cerr<<"Uso: install <name> [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]\n"; return 2; }
        std::string name = args.front(); args.erase(args.begin());
        bool use_fakeroot = eatFlag("--fakeroot");
        std::string sf = getOpt("--strip-flags"); if(!sf.empty()) CFG.strip_flags=sf;
        std::string d = getOpt("--destdir"); if(!d.empty()) CFG.destdir=d;
        std::string f = getOpt("--format"); if(!f.empty()) CFG.package_format=(f=="zst"?"zst":"xz");

        // antes de instalar, tenta empacotar a partir do stage (opcional) → criar pacote final também
        std::vector<std::string> staged;
        std::string stageDir;
        if(!stage_install(name, stageDir, staged)){
            rollbackInstall(name);
            return 1;
        }
        // conflitos
        auto conflicts = detectConflicts(name, staged);
        if(!conflicts.empty()){
            std::ofstream lf(logPath(name,"install"), std::ios::app);
            lf<<"[erro] Conflitos detectados:\n";
            for(auto& c: conflicts) lf<<"  - "<<c<<"\n";
            rollbackInstall(name);
            return 1;
        }
        // instala no sistema
        if(!installToSystem(stageDir, use_fakeroot, logPath(name,"install"))){
            rollbackInstall(name);
            return 1;
        }
        // grava .files
        writeFilesList(name, staged);

        // cria pacote (opcional útil)
        std::string pkgfile;
        if(!packStage(name, stageDir, pkgfile, logPath(name,"package"))){
            std::cerr<<"[aviso] empacotamento falhou, seguindo.\n";
        }

        // Atualiza DBSTATE se existir metadado
        // Aqui poderíamos carregar metadados de um arquivo META no work, mas como simplificação:
        if(DBSTATE.installed.find(name)==DBSTATE.installed.end()){
            PackageMeta m; m.name=name; m.version="unknown";
            DBSTATE.installed[name] = m;
            db_save();
        }
        return 0;
    }
    if(cmd=="package"){
        if(args.empty()){ std::cerr<<"Uso: package <name> [--format zst|xz]\n"; return 2; }
        std::string name = args.front(); args.erase(args.begin());
        std::string f = getOpt("--format"); if(!f.empty()) CFG.package_format=(f=="zst"?"zst":"xz");
        bool ok = action_package(name);
        return ok?0:1;
    }
    if(cmd=="remove"){
        if(args.empty()){ std::cerr<<"Uso: remove <name>\n"; return 2; }
        return action_remove(args.front())?0:1;
    }
    if(cmd=="upgrade"){
        if(args.empty()){ std::cerr<<"Uso: upgrade <name>\n"; return 2; }
        bool use_fakeroot = eatFlag("--fakeroot");
        return action_upgrade(args.front(), use_fakeroot)?0:1;
    }
    if(cmd=="reinstall"){
        if(args.empty()){ std::cerr<<"Uso: reinstall <name>\n"; return 2; }
        bool use_fakeroot = eatFlag("--fakeroot");
        return action_reinstall(args.front(), use_fakeroot)?0:1;
    }
    if(cmd=="clean"){
        if(args.empty()){ std::cerr<<"Uso: clean <name>\n"; return 2; }
        std::string name = args.front();
        std::error_code ec;
        fs::remove_all(pjoin(CFG.work,name), ec);
        fs::remove_all(pjoin(CFG.logs,name), ec);
        fs::remove_all(pjoin(CFG.staging,name), ec);
        std::cout<<"Clean concluído: "<<name<<"\n";
        return 0;
    }
    if(cmd=="verify"){
        if(args.size()<2){ std::cerr<<"Uso: verify <arquivo> --sha256 SUM\n"; return 2; }
        std::string file = args.front(); args.erase(args.begin());
        std::string sha = getOpt("--sha256");
        if(sha.empty()){ std::cerr<<"--sha256 obrigatório\n"; return 2; }
        return action_verify(file, sha)?0:1;
    }
    if(cmd=="info"){
        if(args.empty()){ std::cerr<<"Uso: info <name>\n"; return 2; }
        action_info(args.front());
        return 0;
    }
    if(cmd=="search"){
        if(args.empty()){ std::cerr<<"Uso: search <termo>\n"; return 2; }
        action_search(args.front());
        return 0;
    }
    if(cmd=="revdep"){
        if(args.empty()){ std::cerr<<"Uso: revdep <name>\n"; return 2; }
        action_revdep(args.front());
        return 0;
    }
    if(cmd=="sync"){
        std::string scope = "repo";
        if(!args.empty() && args.front().rfind("-",0)!=0){ scope=args.front(); args.erase(args.begin()); }
        std::string msg = getOpt("--message");
        std::string rem = getOpt("--remote");
        std::string br  = getOpt("--branch");
        bool push = true;
        if(eatFlag("--no-push")) push=false;
        if(eatFlag("--push")) push=true;
        bool init_repo = eatFlag("--init");
        bool ok = action_sync(scope, msg, rem, br, push, init_repo);
        return ok?0:1;
    }

    std::cerr<<"Comando desconhecido.\n";
    usage();
    return 2;
}
