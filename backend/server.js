import express from "express";
import fetch from "node-fetch";
import passport from "passport";
import { Strategy as DiscordStrategy } from "passport-discord";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Sequelize, DataTypes, Op } from "sequelize";
import crypto from "crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import swaggerJsDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config({path: "../.env"});

const app = express();
const ADDRESS = process.env.ADDRESS;
const PORT = process.env.PORT;
const SWAGGER = process.env.SWAGGER;
const ACCESS_TOKEN_KEY = process.env.ACCESS_TOKEN_KEY;
const REFRESH_TOKEN_KEY = process.env.REFRESH_TOKEN_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DOTPAY_ID = process.env.DOTPAY_ID;
const DOTPAY_PIN = process.env.DOTPAY_PIN;

app.use(
    cors({
        credentials: true,
        origin: ["https://bd-lab-1.onrender.com", "http://localhost:5173", "http://192.168.0.1:5173"],
        methods: ["OPTIONS", "GET", "POST", "PATCH", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
        exposedHeaders: ["Content-Length", "Content-Type"],
        optionsSuccessStatus: 200
    })
);

app.options('*', cors());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Zbyt wiele żądań, spróbuj ponownie później." }
});

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
    return done(null, { profile, accessToken });
}));

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(express.json());
app.use(limiter);
app.use(express.urlencoded({ extended: true }));

app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: { policy: "unsafe-none" },
    contentSecurityPolicy: false
}));

app.use((req, res, next) => {
    const allowedMethods = ["OPTIONS", "GET", "POST", "PATCH", "DELETE"];
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ error: "Metoda HTTP niedozwolona." });
    }
    next();
});

app.use((req, res, next) => {
    if (req.headers["x-http-method-override"]) {
        return res.status(403).json({ error: "Niedozwolone nadpisywanie metody HTTP." });
    }
    next();
});

app.disable("x-powered-by");

const sequelize = new Sequelize({
    dialect: "sqlite",
    storage: "users.db"
});

const User = sequelize.define("User", {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    username: {
        type: DataTypes.STRING,
        validate: { len: [5, 20] },
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.STRING,
        validate: { isEmail: true, len: [6, 320] },
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        validate: { len: [40, 80] },
        allowNull: false
    },
    avatar: {
        type: DataTypes.STRING,
        validate: { isUrl: true, len: [0, 500] },
        allowNull: true
    },
    github_id: {
        type: DataTypes.STRING,
        validate: { len: [0, 9] },
        allowNull: true,
        unique: true
    },
    discord_id: {
        type: DataTypes.STRING,
        validate: { len: [0, 18] },
        allowNull: true,
        unique: true
    }
});

const Product = sequelize.define("Product", 
{
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    product: {
        type: DataTypes.STRING,
        validate: { len: [3, 20] },
        allowNull: false
    }
});

const Blacklist = sequelize.define("Blacklist", {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    jti: {
        type: DataTypes.STRING,
        validate: { len: [0, 36] },
        allowNull: false,
        unique: true
    },
    expires_at: {
        type: DataTypes.DATE,
        validate: { isDate: true },
        allowNull: false
    },
});

const Subscription = sequelize.define("Subscription", {
    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    plan: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            isIn: [['PREMIUM', 'PREMIUM+']]
        }
    },
    start_date: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
    },
    end_date: {
        type: DataTypes.DATE,
        allowNull: false
    },
    payment_id: {
        type: DataTypes.STRING,
        allowNull: true
    },
    status: {
        type: DataTypes.STRING,
        defaultValue: 'PENDING',
        validate: {
            isIn: [['PENDING', 'ACTIVE', 'EXPIRED', 'CANCELLED']]
        }
    }
});

const UserProduct = sequelize.define("UserProduct", {});
User.hasMany(Subscription);
Subscription.belongsTo(User);
User.belongsToMany(Product, { through: UserProduct });
Product.belongsToMany(User, { through: UserProduct });

sequelize.sync()
    .then(() => {
        console.log("Baza danych zaktualizowana.");
        return initAdminAccount();
    })
    .then(() => {
        return cleanupExpiredTokens();
    })
    .then(() => {
        console.log("Inicjalizacja serwera zakończona.");
    })
    .catch((err) => {
        console.error("Błąd podczas synchronizacji bazy danych, inicjalizacji konta administratora lub czyszczenia wygasłych tokenów z blacklisty: ", err);
    });

const cleanupExpiredTokens = async () => {
    try {
        const currentDate = new Date();
        const deletedCount = await Blacklist.destroy({
            where: {
                expires_at: {
                    [Op.lt]: currentDate
                }
            }
        });
        console.log(`Usunięto ${deletedCount} wygasłych tokenów z blacklisty.`);
    } catch (error) {
        console.error("Błąd podczas czyszczenia wygasłych tokenów z blacklisty: ", error);
    }
};

const initAdminAccount = async () => {
    try {
        if (!ADMIN_USERNAME || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
            console.warn("Brak danych administratora w pliku .env. Konto administratora nie zostało utworzone.");
            return;
        }

        const existingAdmin = await User.findOne({
            where: { 
                [Op.or]: [
                    sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('username')), 
                        sequelize.fn('LOWER', ADMIN_USERNAME)
                    ),
                    sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('email')), 
                        sequelize.fn('LOWER', ADMIN_EMAIL)
                    )
                ]
            }
        });

        if (existingAdmin) {
            console.log("Konto administratora już istnieje.");
            return;
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, salt);

        await User.create({
            username: ADMIN_USERNAME,
            email: ADMIN_EMAIL,
            password: hashedPassword
        });

        console.log("Konto administratora zostało utworzone.");
    } catch (error) {
        console.error("Błąd podczas tworzenia konta administratora: ", error);
    }
};

const jwtAuth = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: "Brak nagłówka Authorization." });
    }

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Niepoprawny format nagłówka Authorization." });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ error: "Brak lub nieprawidłowy format access tokenu." });
    }

    try {
        const decoded = jwt.verify(token, ACCESS_TOKEN_KEY);
        const jti = decoded.jti || token.substring(0, 36);
        
        const blacklistedToken = await Blacklist.findOne({ where: { jti } });
        if (blacklistedToken) {
            return res.status(401).json({ error: "Access token został unieważniony." });
        }
        
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Niepoprawny access token." });
    }
};

const swaggerOptions = {
    swaggerDefinition: {
        openapi: "3.0.0",
        info: {
            title: "API Produktów",
            version: "1.0",
            description: "API do zarządzania produktami",
            contact: {
                name: "Wsparcie API",
                email: "support@example.com"
            },
            license: {
                name: "MIT",
                url: "https://opensource.org/licenses/MIT"
            }
        },
        servers: [{ url: `${ADDRESS}${PORT}` }],
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT"
                }
            }
        },
        security: [
            {
                BearerAuth: []
            }
        ]
    },
    apis: ["./server.js"]
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use(SWAGGER, swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @swagger
 * /api/delete-account/{username}:
 *   delete:
 *     summary: Usuń konto użytkownika
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: username
 *         in: path
 *         required: true
 *         description: Nazwa użytkownika (5-20 znaków, bez spacji, bez polskich znaków)
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Konto użytkownika usunięte pomyślnie
 *       403:
 *         description: Brak uprawnień do usunięcia tego konta (tylko właściciel konta lub administrator może usunąć konto)
 *       404:
 *         description: Użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.delete("/api/delete-account/:username", jwtAuth, async (req, res) => {
    try {
        const user = await User.findOne({
            where: sequelize.where(
                sequelize.fn('LOWER', sequelize.col('username')), 
                sequelize.fn('LOWER', req.params.username)
            )
        });
        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }
        
        if (user.username === req.user.username || req.user.username === ADMIN_USERNAME) {
            await user.destroy();
            return res.status(200).json({ message: "Użytkownik usunięty." });
        } else {
            return res.status(403).json({ error: "Nie masz uprawnień do usunięcia konta tego użytkownika." });
        }
    } catch (error) {
        console.error("Błąd podczas usuwania użytkownika:", error);
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/user/{username}:
 *   get:
 *     summary: Pobierz informacje o użytkowniku
 *     parameters:
 *       - name: username
 *         in: path
 *         required: true
 *         description: Nazwa użytkownika (5-20 znaków, bez spacji, bez polskich znaków)
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Informacje o użytkowniku pobrane pomyślnie
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                 email:
 *                   type: string
 *                 avatar_url:
 *                   type: string
 *       404:
 *         description: Użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/user/:username", async (req, res) => {
    try {
        const user = await User.findOne({
            where: sequelize.where(
                sequelize.fn('LOWER', sequelize.col('username')), 
                sequelize.fn('LOWER', req.params.username)
            )
        });

        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        res.status(200).json({ username: user.username, email: user.email, avatar_url: user.avatar, github_id: user.github_id, discord_id: user.discord_id, account_created: user.createdAt.toISOString() });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Rejestracja nowego użytkownika
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: (5-20 znaków, bez spacji, bez polskich znaków)
 *               email:
 *                 type: string
 *                 description: Adres email użytkownika (6-320 znaków, bez spacji, bez polskich znaków)
 *               password:
 *                 type: string
 *                 description: Hasło (8-20 znaków, minimum jedna mała litera, jedna wielka litera, jedna cyfra i znak specjalny, bez spacji, bez polskich znaków)
 *     responses:
 *       201:
 *         description: Zarejestrowano pomyślnie
 *       400:
 *         description: Brak wszystkich danych, niepoprawna nazwa użytkownika, email lub hasło
 *       409:
 *         description: Nazwa użytkownika lub email zajęty
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: "Brak wszystkich danych." });
        }

        if (username.length < 5 || username.length > 20 || username.includes(" ") || username.includes(" ") || /[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/.test(username)) {
            return res.status(400).json({ error: "Niepoprawna nazwa użytkownika. Długość 5-20 znaków, bez polskich znaków, bez spacji." });
        }

        if (email.length < 6 || email.length > 320 || !email.includes("@") || !email.includes(".") || email.includes(" ")) {
            return res.status(400).json({ error: "Niepoprawny email. Wymagany znak @, domena i kropka. Długość 6-320 znaków, bez polskich znaków, bez spacji." });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>])(?!.*[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]).{8,20}$/;
        if (!passwordRegex.test(password) || password.includes(" ")) {
            return res.status(400).json({ error: "Niepoprawne hasło. Wymagana co najmniej jedna mała litera, jedna wielka litera, cyfra oraz znak specjalny. Długość 8-20 znaków, bez polskich znaków, bez spacji." });
        }

        const existingUserByUsername = await User.findOne({ where: { username } });
        if (existingUserByUsername) {
            return res.status(409).json({ error: "Nazwa użytkownika zajęta." });
        }

        const existingUserByEmail = await User.findOne({ where: { email } });
        if (existingUserByEmail) {
            return res.status(409).json({ error: "Email zajęty." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({ username, email, password: hashedPassword });

        const access_jti = crypto.randomUUID();
        const refresh_jti = crypto.randomUUID();
        const access_token_expiresIn = "00:00:10:00";
        const refresh_token_expiresIn = "00:01:00:00";
        const access_token = jwt.sign({ id: newUser.id, username: newUser.username, jti: access_jti }, ACCESS_TOKEN_KEY, { expiresIn: '10m' });
        const refresh_token = jwt.sign({ id: newUser.id, username: newUser.username, jti: refresh_jti }, REFRESH_TOKEN_KEY, { expiresIn: '1h' });

        res.status(201).json({ message: "Zarejestrowano pomyślnie.", username: newUser.username, email: newUser.email, access_token: access_token, refresh_token: refresh_token, expire_time: access_token_expiresIn.toString(), refresh_expire_time: refresh_token_expiresIn.toString()});
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
* @swagger
* /api/login:
*   post:
*     summary: Logowanie użytkownika
*     requestBody:
*       required: true
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               usernameOrEmail:
*                 type: string
*                 description: Nazwa użytkownika lub adres email
*               password:
*                 type: string
*                 description: Hasło użytkownika
*               remember:
*                 type: boolean
*                 description: Czy użytkownik chce być zaolgowany przez dłuższy czas (również po zamknięciu karty czy przeglądarki)
*     responses:
*       200:
*         description: Zalogowano pomyślnie
*       400:
*         description: Brak wszystkich danych
*       401:
*         description: Nieprawidłowe dane logowania
*       404:
*         description: Użytkownik nie znaleziony
*       500:
*         description: Wystąpił błąd serwera
*/

app.post("/api/login", async (req, res) => {
    try {
        const { usernameOrEmail, password, remember } = req.body;

        if (!usernameOrEmail || !password) {
            return res.status(400).json({ error: "Brak wszystkich danych." });
        }

        const user = await User.findOne({
            where: { 
                [Op.or]: [
                    sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('username')), 
                        sequelize.fn('LOWER', usernameOrEmail)
                    ),
                    sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('email')), 
                        sequelize.fn('LOWER', usernameOrEmail)
                    )
                ] 
            }
        });

        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Nieprawidłowe dane logowania." });
        }

        const access_jti = crypto.randomUUID();
        const refresh_jti = crypto.randomUUID();
        const access_token_expiresIn = "00:00:10:00";
        const refresh_token_expiresIn = remember ? "01:00:00:00" : "00:01:00:00";

        const access_token = jwt.sign({ id: user.id, username: user.username, jti: access_jti }, ACCESS_TOKEN_KEY, { expiresIn: '10m' });
        const refresh_token = jwt.sign({ id: user.id, username: user.username, jti: refresh_jti }, REFRESH_TOKEN_KEY, { expiresIn: remember ? '1d' : '1h' });

        res.status(200).json({ message: "Zalogowano pomyślnie.", username: user.username, email: user.email, access_token: access_token, refresh_token: refresh_token, expire_time: access_token_expiresIn.toString(), refresh_expire_time: refresh_token_expiresIn.toString()});
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/logout:
 *   post:
 *     summary: Wylogowanie użytkownika
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Wylogowano pomyślnie
 *       400:
 *         description: Brak refresh tokenu
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/logout", async (req, res) => {
    try {
        const { refresh_token } = req.body;
        if (!refresh_token) {
            return res.status(400).json({ error: "Brak refresh tokenu." });
        }
        const access_token = req.headers.authorization.split(" ")[1];

        const decodedAccessToken = jwt.decode(access_token);
        const decodedRefreshToken = jwt.decode(refresh_token);
        
        const accessTokenExpiresAt = new Date(decodedAccessToken.exp * 1000);
        const refreshTokenExpiresAt = new Date(decodedRefreshToken.exp * 1000);

        await Blacklist.upsert({ 
            jti: decodedAccessToken.jti, 
            expires_at: accessTokenExpiresAt 
        });
        
        await Blacklist.upsert({ 
            jti: decodedRefreshToken.jti, 
            expires_at: refreshTokenExpiresAt 
        });

        res.status(200).json({ message: "Wylogowano pomyślnie." });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/refresh:
 *   post:
 *     summary: Odświeżenie tokenów
 *     requestBody:
 *       required: true
 *       description: Refresh token
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refresh_token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tokeny odświeżone pomyślnie
 *       400:
 *         description: Brak refresh tokenu
 *       401:
 *         description: Refresh token został unieważniony
 *       404:
 *         description: Użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/refresh", async (req, res) => {
    try {
        const { refresh_token } = req.body;
        if (!refresh_token) {
            return res.status(400).json({ error: "Brak refresh tokenu." });
        }

        try {
            const refreshTokenVerified = jwt.verify(refresh_token, REFRESH_TOKEN_KEY);
            const blacklistedRefreshToken = await Blacklist.findOne({ where: { jti: refreshTokenVerified.jti }});
            
            if (blacklistedRefreshToken) {
                return res.status(401).json({ error: "Refresh token został unieważniony." });
            }
            
            const user = await User.findByPk(refreshTokenVerified.id);
            if (!user) {
                return res.status(404).json({ error: "Użytkownik nie znaleziony." });
            }

            const access_jti = crypto.randomUUID();
            const refresh_jti = crypto.randomUUID();
            const access_token_expiresIn = "00:00:10:00";
            const refresh_token_expiresIn = "00:01:00:00";
            const new_access_token = jwt.sign({ id: user.id, username: user.username, jti: access_jti }, ACCESS_TOKEN_KEY, { expiresIn: '10m' });
            const new_refresh_token = jwt.sign({ id: user.id, username: user.username, jti: refresh_jti }, REFRESH_TOKEN_KEY, { expiresIn: '1h' });
            
            res.status(200).json({ message: "Odświeżono tokeny.", username: user.username, email: user.email, access_token: new_access_token, refresh_token: new_refresh_token, expire_time: access_token_expiresIn.toString(), refresh_expire_time: refresh_token_expiresIn.toString() });
        } catch (verifyError) {
            return res.status(401).json({ error: "Nieprawidłowy refresh token." });
        }
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/clear-session:
 *   get:
 *     summary: Usunięcie ciasteczka sesji
 *     responses:
 *       200:
 *         description: Ciasteczko sesji usunięte
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/clear-session", async (req, res) => {
    try {
        res.clearCookie("session");
        res.status(200).json({ message: "Ciasteczko 'session' usunięte." });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/products:
 *   get:
 *     summary: Pobierz wszystkie produkty użytkownika
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Lista produktów lub użytkownik nie ma produktów
 *       404:
 *         description: Użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/products", jwtAuth, async (req, res) => 
{
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        const products = await user.getProducts();
        if (products.length === 0) 
        {
            return res.status(200).json({ message: "Użytkownik nie ma produktów." });
        }

        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/product/{id}:
 *   get:
 *     summary: Pobierz produkt użytkownika po ID
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID produktu
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Dane produktu
 *       404:
 *         description: Produkt bądź użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/product/:id", jwtAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ message: "Użytkownik nie znaleziony." });
        }

        const products = await user.getProducts({ where: { id: req.params.id } });
        if (!products || products.length === 0) {
            return res.status(404).json({ message: "Produkt nie znaleziony." });
        }

        res.status(200).json(products[0]);
    } catch (error) {
        res.status(500).json({ message: "Wystąpił błąd serwera." });
    }
});


/**
 * @swagger
 * /api/add-product:
 *   post:
 *     summary: Dodaj nowy produkt
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       description: Nazwa produktu
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               product:
 *                 type: string
 *     responses:
 *       201:
 *         description: Produkt dodany
 *       400:
 *         description: Za krótka lub za długa nazwa produktu
 *       404:
 *         description: Użytkownik nie znaleziony
 *       409:
 *         description: Taki produkt już istnieje
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/add-product", jwtAuth, async (req, res) => {
    try {
        const { product } = req.body;

        if (!product || product.length < 3 || product.length > 20) {
            return res.status(400).json({ error: "Nazwa produktu musi zawierać od 3 do 20 znaków." });
        }

        let existingProduct = await Product.findOne({ where: { product } });

        if (!existingProduct) {
            existingProduct = await Product.create({ product });
        }

        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        const hasProduct = await user.hasProduct(existingProduct);
        if (hasProduct) {
            return res.status(409).json({ error: "Taki produkt już istnieje." });
        }

        await user.addProduct(existingProduct);

        res.status(201).json({ message: "Produkt dodany.", product: existingProduct });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/delete-product/{id}:
 *   delete:
 *     summary: Usuń produkt
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID produktu
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Produkt usunięty
 *       403:
 *         description: Produkt nie przypisany do użytkownika
 *       404:
 *         description: Produkt lub użytkownik nie znaleziony
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.delete("/api/delete-product/:id", jwtAuth, async (req, res) => {
    try {
        const { id } = req.params;

        const user = await User.findByPk(req.user.id, { include: Product });

        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const product = await Product.findByPk(id);
        if (!product) {
            return res.status(404).json({ message: "Nie znaleziono produktu." });
        }

        const hasProduct = await user.hasProduct(product);
        if (!hasProduct) {
            return res.status(403).json({ message: "Nie masz dostępu do tego produktu." });
        }

        await user.removeProduct(product);

        const productUsers = await product.getUsers();
        if (productUsers.length === 0) {
            await product.destroy();
        }

        res.status(200).json({ message: "Produkt usunięty." });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/edit-product/{id}:
 *   patch:
 *     summary: Edytuj produkt
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       description: Nazwa produktu
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               product:
 *                 type: string
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID produktu
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Produkt zaktualizowany
 *       400:
 *         description: Za krótka lub za długa nazwa produktu
 *       403:
 *         description: Produkt nie przypisany do użytkownika
 *       404:
 *         description: Produkt lub użytkownik nie znaleziony
 *       409:
 *         description: Produkt ma już taką nazwę
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.patch("/api/edit-product/:id", jwtAuth, async (req, res) => {
    try {
        const { product } = req.body;
        const { id } = req.params;

        const user = await User.findByPk(req.user.id, { include: Product });

        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const existingProduct = await Product.findByPk(id);
        if (!existingProduct) {
            return res.status(404).json({ message: "Nie znaleziono produktu." });
        }

        const hasProduct = await user.hasProduct(existingProduct);
        if (!hasProduct) {
            return res.status(403).json({ message: "Produkt nie przypisany do użytkownika." });
        }

        if (existingProduct.product === product) {
            return res.status(409).json({ message: "Produkt ma już taką nazwę." });
        }

        if (product.length < 3 || product.length > 20) {
            return res.status(400).json({ error: "Nazwa produktu musi zawierać od 3 do 20 znaków." });
        }

        const productWithSameName = await Product.findOne({
            where: {
                product: product,
                id: { [Op.ne]: id }
            }
        });

        if (productWithSameName) {
            return res.status(409).json({ message: "Produkt o tej nazwie już istnieje w bazie danych." });
        }

        existingProduct.product = product;
        await existingProduct.save();

        res.status(200).json({ message: "Produkt zaktualizowany w bazie danych.", product: existingProduct });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/login/github:
 *   get:
 *     summary: Inicjuje proces logowania przez GitHub
 *     description: Przekierowuje użytkownika do strony autoryzacji GitHub
 *     responses:
 *       302:
 *         description: Przekierowanie do strony logowania GitHub
 *       429:
 *         description: Zbyt wiele żądań, limit 10 na godzinę
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/login/github", (req, res, next) => {
    passport.authenticate('github')(req, res, next);
});

/**
 * @swagger
 * /api/auth/github:
 *   get:
 *     summary: Obsługuje callback po autoryzacji GitHub
 *     description: Przetwarza dane z GitHub i tworzy/loguje użytkownika
 *     parameters:
 *       - name: code
 *         in: query
 *         description: Kod autoryzacyjny z GitHub
 *         schema:
 *           type: string
 *       - name: error
 *         in: query
 *         description: Błąd z GitHub (jeśli występuje)
 *         schema:
 *           type: string
 *       - name: link
 *         in: query
 *         description: Czy powiązać konto z istniejącym kontem (true/false)
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Przekierowanie do strony głównej po pomyślnym logowaniu
 *       400:
 *         description: Nie udało się pobrać adresu email lub próba powiązania z innym kontem GitHub
 *       401:
 *         description: Błąd autoryzacji lub nieprawidłowy token JWT
 *       404:
 *         description: Nie znaleziono użytkownika
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/auth/github", async (req, res, next) => {
    try {
        if (req.query.error === "access_denied") {
            res.clearCookie("session");
            return res.redirect("https://bd-lab-1.onrender.com/login");
        }

        passport.authenticate('github', async (err, authData) => {
            if (err) {
                return res.status(500).json({ error: `Błąd podczas uwierzytelnienia GitHub: ${err.message}` });
            }
            
            if (!authData) {
                return res.status(401).json({ error: "Nieudane uwierzytelnienie GitHub." });
            }

            const { profile, accessToken } = authData;
            
            const github_id = profile.id.toString();
            let username = profile.username;
            let email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
            const avatar_url = profile.photos && profile.photos.length > 0 ? profile.photos[0].value : null;
            
            if (!email && accessToken) {
                try {
                    const response = await fetch('https://api.github.com/user/emails', {
                        headers: {
                            'Authorization': `token ${accessToken}`,
                            'User-Agent': 'BD_Lab-App'
                        }
                    });
                    
                    if (response.ok) {
                        const emails = await response.json();
                        for (const em of emails) {
                            if (em.primary && em.verified) {
                                email = em.email;
                                break;
                            }
                        }
                    }
                } catch (error) {
                    console.error("Błąd podczas pobierania adresu email z GitHub: ", error);
                }
            }
            
            if (!email) {
                return res.status(400).json({ error: "Nie udało się pobrać adresu email z GitHub." });
            }

            const link_account = req.query.link === "true";
            
            if (link_account) {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith("Bearer ")) {
                    return res.status(401).json({ error: "Brak tokenu JWT do powiązania konta." });
                }
                
                try {
                    const token = authHeader.split(" ")[1];
                    const decoded = jwt.verify(token, ACCESS_TOKEN_KEY);
                    const current_user = await User.findByPk(decoded.id);
                    
                    if (!current_user) {
                        return res.status(404).json({ error: "Nie znaleziono użytkownika." });
                    }
                    
                    if (current_user.github_id && current_user.github_id !== github_id) {
                        return res.status(400).json({ error: "Twoje konto jest już powiązane z innym GitHub." });
                    }
                    
                    current_user.github_id = github_id;
                    if (!current_user.avatar && avatar_url) {
                        current_user.avatar = avatar_url;
                    }
                    
                    await current_user.save();
                    return res.status(200).json({ message: "Konto GitHub zostało pomyślnie powiązane." });
                } catch (error) {
                    return res.status(401).json({ error: "Nieprawidłowy token JWT." });
                }
            }

            let user = await User.findOne({
                where: {
                    [Op.or]: [
                        { github_id },
                        sequelize.where(sequelize.fn('LOWER', sequelize.col('username')), sequelize.fn('LOWER', username)),
                        sequelize.where(sequelize.fn('LOWER', sequelize.col('email')), sequelize.fn('LOWER', email))
                    ]
                }
            });

            if (user) {
                if (!user.github_id) {
                    user.github_id = github_id;
                }
                if (!user.avatar && avatar_url) {
                    user.avatar = avatar_url;
                }
                await user.save();
            } else {
                let finalUsername = username;
                const existingUser = await User.findOne({
                    where: sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('username')), 
                        sequelize.fn('LOWER', username)
                    )
                });
                
                if (existingUser) {
                    finalUsername = `${username}_${Math.floor(Math.random() * 9000) + 1000}`;
                }

                const salt = await bcrypt.genSalt(10);
                const randomPassword = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), salt);
                
                user = await User.create({
                    username: finalUsername,
                    email,
                    password: randomPassword,
                    avatar: avatar_url,
                    github_id
                });
            }

            const access_jti = crypto.randomUUID();
            const refresh_jti = crypto.randomUUID();
            const access_token_expiresIn = "00:00:10:00";
            const refresh_token_expiresIn = remember ? "01:00:00:00" : "00:01:00:00";
            
            const access_token = jwt.sign({ id: user.id, username: user.username, jti: access_jti }, ACCESS_TOKEN_KEY, { expiresIn: "10m" });
            const refresh_token = jwt.sign({ id: user.id, username: user.username, jti: refresh_jti }, REFRESH_TOKEN_KEY, { expiresIn: "1d" });

            return res.redirect(`https://bd-lab-1.onrender.com/auth-callback?username=${encodeURIComponent(user.username)}&email=${encodeURIComponent(user.email)}&access_token=${encodeURIComponent(access_token)}&refresh_token=${encodeURIComponent(refresh_token)}&expire_time=${encodeURIComponent(access_token_expiresIn.toString())}&refresh_expire_time=${encodeURIComponent(refresh_token_expiresIn.toString())}`);
            
        })(req, res, next);
    } catch (error) {
        return res.status(500).json({ error: `Błąd podczas uwierzytelnienia GitHub: ${error.message}` });
    }
});

/**
 * @swagger
 * /api/login/discord:
 *   get:
 *     summary: Inicjuje proces logowania przez Discord
 *     description: Przekierowuje użytkownika do strony autoryzacji Discord
 *     responses:
 *       302:
 *         description: Przekierowanie do strony logowania Discord
 *       429:
 *         description: Zbyt wiele żądań, limit 10 na godzinę
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/login/discord", (req, res, next) => {
    passport.authenticate('discord')(req, res, next);
});

/**
 * @swagger
 * /api/auth/discord:
 *   get:
 *     summary: Obsługuje callback po autoryzacji Discord
 *     description: Przetwarza dane z Discord i tworzy/loguje użytkownika
 *     parameters:
 *       - name: code
 *         in: query
 *         description: Kod autoryzacyjny z Discord
 *         schema:
 *           type: string
 *       - name: error
 *         in: query
 *         description: Błąd z Discord (jeśli występuje)
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Przekierowanie do strony głównej po pomyślnym logowaniu
 *       400:
 *         description: Nie udało się pobrać adresu email z Discord
 *       401:
 *         description: Błąd autoryzacji
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/auth/discord", async (req, res, next) => {
    try {
        if (req.query.error === "access_denied") {
            res.clearCookie("session");
            return res.redirect("https://bd-lab-1.onrender.com/login");
        }

        passport.authenticate('discord', async (err, discordUser) => {
            if (err) {
                return res.status(500).json({ error: `Błąd podczas uwierzytelnienia Discord: ${err.message}` });
            }
            
            if (!discordUser) {
                return res.status(401).json({ error: "Nieudane uwierzytelnienie Discord." });
            }

            const discord_id = discordUser.id;
            const username = discordUser.username;
            const email = discordUser.email;
            const avatar_url = discordUser.avatar 
                ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png` 
                : null;

            if (!email) {
                return res.status(400).json({ error: "Nie udało się pobrać adresu email z Discord." });
            }

            let user = await User.findOne({
                where: {
                    [Op.or]: [
                        { discord_id },
                        sequelize.where(sequelize.fn('LOWER', sequelize.col('username')), sequelize.fn('LOWER', username)),
                        sequelize.where(sequelize.fn('LOWER', sequelize.col('email')), sequelize.fn('LOWER', email))
                    ]
                }
            });

            if (user) {
                if (!user.discord_id) {
                    user.discord_id = discord_id;
                }
                if (!user.avatar && avatar_url) {
                    user.avatar = avatar_url;
                }
                await user.save();
            } else {
                let finalUsername = username;
                const existingUser = await User.findOne({
                    where: sequelize.where(
                        sequelize.fn('LOWER', sequelize.col('username')), 
                        sequelize.fn('LOWER', username)
                    )
                });
                
                if (existingUser) {
                    finalUsername = `${username}_${Math.floor(Math.random() * 9000) + 1000}`;
                }

                const salt = await bcrypt.genSalt(10);
                const randomPassword = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), salt);
                
                user = await User.create({
                    username: finalUsername,
                    email,
                    password: randomPassword,
                    avatar: avatar_url,
                    discord_id
                });
            }

            const access_jti = crypto.randomUUID();
            const refresh_jti = crypto.randomUUID();
            const access_token_expiresIn = "00:00:10:00";
            const refresh_token_expiresIn = remember ? "01:00:00:00" : "00:01:00:00";
            
            const access_token = jwt.sign({ id: user.id, username: user.username, jti: access_jti }, ACCESS_TOKEN_KEY, { expiresIn: "10m" });
            const refresh_token = jwt.sign({ id: user.id, username: user.username, jti: refresh_jti }, REFRESH_TOKEN_KEY, { expiresIn: "1d" });

            return res.redirect(`https://bd-lab-1.onrender.com/auth-callback?username=${encodeURIComponent(user.username)}&email=${encodeURIComponent(user.email)}&access_token=${encodeURIComponent(access_token)}&refresh_token=${encodeURIComponent(refresh_token)}&expire_time=${encodeURIComponent(access_token_expiresIn.toString())}&refresh_expire_time=${encodeURIComponent(refresh_token_expiresIn.toString())}`);
            
        })(req, res, next);
    } catch (error) {
        return res.status(500).json({ error: `Błąd podczas uwierzytelnienia Discord: ${error.message}` });
    }
});

/**
 * @swagger
 * /api/payments/create:
 *   post:
 *     summary: Inicjuje zakup pakietu PREMIUM lub PREMIUM+
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               plan:
 *                 type: string
 *                 enum: [PREMIUM, PREMIUM+]
 *     responses:
 *       200:
 *         description: Przekierowanie do bramki płatności
 *       400:
 *         description: Nieprawidłowy plan
 *       404:
 *         description: Nie znaleziono użytkownika
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/payments/create", jwtAuth, async (req, res) => {
    try {
        const { plan } = req.body;
        
        if (!plan || !['PREMIUM', 'PREMIUM+'].includes(plan)) {
            return res.status(400).json({ error: "Nieprawidłowy plan. Wybierz PREMIUM lub PREMIUM+." });
        }
        
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }
        
        const endDate = new Date();
        endDate.setDate(endDate.getDate() + 30);
        
        const subscription = await Subscription.create({
            UserId: user.id,
            plan,
            end_date: endDate,
            status: 'PENDING'
        });

        function generateSignature(params, pin)
        {
            const kolejnosc = [
                'api_version', 'charset', 'lang', 'id', 'amount', 'currency',
                'description', 'control', 'channel', 'ch_lock', 'URL', 'type', 'buttontext',
                'URLC', 'firstname', 'lastname', 'email', 'street', 'street_n1',
                'street_n2', 'state', 'addr3', 'city', 'postcode', 'phone', 'country',
                'code', 'p_info', 'p_email', 'n_email', 'expiration_date', 'deladdr',
                'recipient_account_number', 'recipient_company', 'recipient_first_name',
                'recipient_last_name', 'recipient_street', 'recipient_postcode',
                'recipient_city', 'application', 'application_version', 'sdk_version',
                'customer', 'payer'
            ];

            const wartosci = kolejnosc.map(klucz => params[klucz] || '');
            const ciag = pin + wartosci.join('');
            return crypto.createHash('sha256').update(ciag).digest('hex');
        }

        const control = `SUB_${subscription.id}_${user.id}_${Date.now()}`;
        subscription.payment_id = control;
        await subscription.save();

        const amount = plan === 'PREMIUM' ? '19.99' : '29.99';
        const description = plan === 'PREMIUM' ? 'Pakiet PREMIUM' : 'Pakiet PREMIUM+';

        const returnUrl = 'https://bd-lab-1.onrender.com/premium';
        const webhookUrl = 'https://bd-lab-1.onrender.com/api/payments/webhook';

        const data = {
            api_version: 'dev',
            id: DOTPAY_ID,
            amount,
            currency: 'PLN',
            description,
            control,
            URL: returnUrl,
            URLC: webhookUrl,
            p_info: user.username,
            p_email: user.email,
            type: '4'
        };

        const chk = generateSignature(data, DOTPAY_PIN);
        data.chk = chk;

        const params = new URLSearchParams(data);
        const payment_url = `https://ssl.dotpay.pl/test_payment/?${params.toString()}`;
        
        res.status(200).json({ message: "Przekierowanie do systemu płatności.", payment_url: payment_url });
        
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/payments/webhook:
 *   post:
 *     summary: Webhook dla powiadomień o płatnościach z Dotpay
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: OK
 *       404:
 *         description: Nie znaleziono użytkownika
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.post("/api/payments/webhook", async (req, res) => {
    try {
        const {
            operation_number,
            operation_type,
            operation_status,
            control,
            email,
            operation_amount,
            operation_currency,
            operation_datetime,
            description
        } = req.body;
        
        if (!operation_number || !operation_type || !operation_status) {
            return res.status(400).json({ error: "Brak wymaganych danych." });
        }

        if (operation_status === "completed" && operation_type === "payment") {
            if (control && control.includes('_')) {
                const parts = control.split('_');
                if (parts.length >= 3) {
                    const subscriptionId = parts[1];
                    const userId = parts[2];
                    
                    const subscription = await Subscription.findOne({
                        where: { 
                            id: subscriptionId,
                            UserId: userId,
                            payment_id: control
                        }
                    });
                    
                    if (subscription) {
                        subscription.status = "ACTIVE";
                        await subscription.save();
                        console.log(`Aktywowano subskrypcję ID: ${subscriptionId}`);
                    }
                }
            } 
            else if (email) {
                const user = await User.findOne({
                    where: { email: email }
                });
                
                if (user) {
                    const pendingSubscription = await Subscription.findOne({
                        where: {
                            UserId: user.id,
                            status: 'PENDING'
                        },
                        order: [['createdAt', 'DESC']]
                    });
                    
                    if (pendingSubscription) {
                        pendingSubscription.status = "ACTIVE";
                        await pendingSubscription.save();
                        console.log(`Aktywowano subskrypcję dla użytkownika ${user.username} na podstawie email`);
                    }
                }
            }
        }
        
        res.status(200).json({ message: "OK" });
        
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /api/payments/status:
 *   get:
 *     summary: Sprawdź status subskrypcji użytkownika
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Status subskrypcji
 *       404:
 *         description: Nie znaleziono użytkownika
 *       500:
 *         description: Wystąpił błąd serwera
 */

app.get("/api/payments/status", jwtAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const subscription = await Subscription.findOne({
            where: {
                UserId: req.user.id
            },
            order: [['end_date', 'DESC']]
        });

        if (!subscription) {
            return res.status(200).json({ 
                message: "Użytkownik nie ma subskrypcji.", 
                has_premium: false, 
                subscription: null 
            });
        }
        
        const isActive = subscription.status === "ACTIVE" && 
                         new Date(subscription.end_date) > new Date();
        
        return res.status(200).json({ 
            message: isActive ? "Użytkownik ma aktywną subskrypcję." : "Użytkownik ma nieaktywną subskrypcję.",
            has_premium: isActive,
            subscription: {
                status: subscription.status,
                plan: subscription.plan,
                end_date: isActive ? subscription.end_date : null
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

app.use((req, res) => {
    res.status(404).json({ error: "Nie znaleziono zasobu." });
});

const server = app.listen(PORT, () => 
{
    const address = server.address();
    
    console.log(`Serwer działa na ${address}:${PORT}`);
    console.log(`Dokumentacja API: ${address}:${PORT}${SWAGGER}`);
});