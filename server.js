const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const DATABASE_FILE = path.join(DATA_DIR, "database.json");

// ================================
// CONFIGURAÇÃO
// ================================

if (!process.env.MANAGER_USER) {
    console.error("ERRO: MANAGER_USER não foi configurado no .env");
    process.exit(1);
}

if (!process.env.MANAGER_PASSWORD) {
    console.error("ERRO: MANAGER_PASSWORD não foi configurado no .env");
    process.exit(1);
}

if (!process.env.SESSION_SECRET) {
    console.error("ERRO: SESSION_SECRET não foi configurado no .env");
    process.exit(1);
}

// ================================
// BANCO DE DADOS
// ================================

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });
}

if (!fs.existsSync(DATABASE_FILE)) {
    const database = {
        members: [],
        site: {
            title: "OLDACK SYSTEM",
            description: "Bem-vindo ao nosso sistema."
        }
    };

    fs.writeFileSync(
        DATABASE_FILE,
        JSON.stringify(database, null, 2)
    );
}

function readDatabase() {
    try {
        return JSON.parse(
            fs.readFileSync(
                DATABASE_FILE,
                "utf8"
            )
        );
    } catch (error) {
        console.error("Erro ao ler banco:", error);

        return {
            members: [],
            site: {
                title: "OLDACK SYSTEM",
                description: "Bem-vindo ao nosso sistema."
            }
        };
    }
}

function saveDatabase(database) {
    fs.writeFileSync(
        DATABASE_FILE,
        JSON.stringify(database, null, 2)
    );
}

// ================================
// MIDDLEWARE
// ================================

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(
    session({
        secret: process.env.SESSION_SECRET,

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// ================================
// SITE
// ================================

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

// ================================
// PROTEÇÃO MANAGER
// ================================

function requireManager(req, res, next) {

    if (
        req.session &&
        req.session.manager === true
    ) {
        return next();
    }

    res.status(401).json({
        message: "Acesso permitido somente ao manager."
    });
}

// ================================
// CADASTRO DE MEMBRO
// ================================

app.post(
    "/api/member/register",
    async (req, res) => {

        try {

            const {
                name,
                user,
                pass
            } = req.body;

            if (!name || !user || !pass) {
                return res.status(400).json({
                    message: "Preencha todos os campos."
                });
            }

            if (
                name.length > 80 ||
                user.length > 40 ||
                pass.length > 100
            ) {
                return res.status(400).json({
                    message: "Um dos campos é muito grande."
                });
            }

            const database = readDatabase();

            const normalizedUser =
                user.trim().toLowerCase();

            const existingMember =
                database.members.find(
                    member =>
                        member.user === normalizedUser
                );

            if (existingMember) {
                return res.status(409).json({
                    message:
                        "Esse login já está cadastrado."
                });
            }

            const passwordHash =
                await bcrypt.hash(pass, 12);

            const newMember = {
                id: Date.now().toString(),
                name: name.trim(),
                user: normalizedUser,
                password: passwordHash,
                createdAt: new Date().toISOString()
            };

            database.members.push(newMember);

            saveDatabase(database);

            res.status(201).json({
                message:
                    "Membro cadastrado com sucesso."
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Erro interno do servidor."
            });
        }
    }
);

// ================================
// LOGIN MEMBRO
// ================================

app.post(
    "/api/member/login",
    async (req, res) => {

        try {

            const {
                user,
                pass
            } = req.body;

            if (!user || !pass) {
                return res.status(400).json({
                    message:
                        "Informe login e senha."
                });
            }

            const database = readDatabase();

            const normalizedUser =
                user.trim().toLowerCase();

            const member =
                database.members.find(
                    m =>
                        m.user === normalizedUser
                );

            if (!member) {
                return res.status(401).json({
                    message:
                        "Login ou senha incorretos."
                });
            }

            const passwordCorrect =
                await bcrypt.compare(
                    pass,
                    member.password
                );

            if (!passwordCorrect) {
                return res.status(401).json({
                    message:
                        "Login ou senha incorretos."
                });
            }

            req.session.memberId =
                member.id;

            req.session.memberName =
                member.name;

            res.json({
                message: "Membro entrou!",
                member: {
                    name: member.name
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                message:
                    "Erro interno do servidor."
            });
        }
    }
);

// ================================
// LOGOUT MEMBRO
// ================================

app.post(
    "/api/member/logout",
    (req, res) => {

        req.session.memberId = null;
        req.session.memberName = null;

        res.json({
            message: "Membro saiu."
        });
    }
);

// ================================
// LOGIN MANAGER
// ================================

app.post(
    "/api/manager/login",
    (req, res) => {

        const {
            user,
            pass
        } = req.body;

        if (!user || !pass) {
            return res.status(400).json({
                message:
                    "Informe login e senha."
            });
        }

        const correctUser =
            user.trim() ===
            process.env.MANAGER_USER;

        const correctPassword =
            pass ===
            process.env.MANAGER_PASSWORD;

        if (!correctUser || !correctPassword) {
            return res.status(401).json({
                message:
                    "Login ou senha incorretos."
            });
        }

        req.session.manager = true;

        res.json({
            message:
                "Manager entrou.",
            manager: true
        });
    }
);

// ================================
// LOGOUT MANAGER
// ================================

app.post(
    "/api/manager/logout",
    (req, res) => {

        req.session.destroy(
            error => {

                if (error) {
                    return res.status(500).json({
                        message:
                            "Erro ao sair."
                    });
                }

                res.json({
                    message:
                        "Manager saiu."
                });
            }
        );
    }
);

// ================================
// VERIFICAR MANAGER
// ================================

app.get(
    "/api/manager/me",
    requireManager,
    (req, res) => {

        res.json({
            loggedIn: true,
            manager: true
        });
    }
);

// ================================
// CONTAR MEMBROS
// ================================

app.get(
    "/api/manager/members/count",
    requireManager,
    (req, res) => {

        const database = readDatabase();

        res.json({
            count:
                database.members.length
        });
    }
);

// ================================
// LISTAR MEMBROS
// ================================

app.get(
    "/api/manager/members",
    requireManager,
    (req, res) => {

        const database = readDatabase();

        const members =
            database.members.map(
                member => ({
                    id: member.id,
                    name: member.name,
                    user: member.user,
                    createdAt: member.createdAt
                })
            );

        res.json({
            members
        });
    }
);

// ================================
// ALTERAR SITE
// ================================

app.put(
    "/api/manager/site",
    requireManager,
    (req, res) => {

        const {
            title,
            description
        } = req.body;

        const database = readDatabase();

        if (
            typeof title === "string" &&
            title.trim()
        ) {
            database.site.title =
                title.trim();
        }

        if (
            typeof description === "string" &&
            description.trim()
        ) {
            database.site.description =
                description.trim();
        }

        saveDatabase(database);

        res.json({
            message:
                "Configurações alteradas.",
            site:
                database.site
        });
    }
);

// ================================
// CONFIGURAÇÕES PÚBLICAS
// ================================

app.get(
    "/api/site",
    (req, res) => {

        const database = readDatabase();

        res.json(
            database.site
        );
    }
);

// ================================
// APAGAR MEMBRO
// ================================

app.delete(
    "/api/manager/members/:id",
    requireManager,
    (req, res) => {

        const database = readDatabase();

        const oldLength =
            database.members.length;

        database.members =
            database.members.filter(
                member =>
                    member.id !== req.params.id
            );

        if (
            database.members.length ===
            oldLength
        ) {
            return res.status(404).json({
                message:
                    "Membro não encontrado."
            });
        }

        saveDatabase(database);

        res.json({
            message:
                "Membro removido."
        });
    }
);

// ================================
// PÁGINA PRINCIPAL
// ================================

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }
);

// ================================
// 404
// ================================

app.use(
    (req, res) => {

        res.status(404).json({
            message:
                "Página ou API não encontrada."
        });
    }
);

// ================================
// INICIAR SERVIDOR
// ================================

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "================================="
        );

        console.log(
            "      OLDACK SYSTEM ONLINE"
        );

        console.log(
            "      http://localhost:" + PORT
        );

        console.log(
            "================================="
        );

        console.log("");
    }
);
