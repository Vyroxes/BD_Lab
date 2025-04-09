import express from "express";
import { Sequelize, DataTypes, Op } from "sequelize";
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
// const ORIGIN = process.env.ORIGIN;

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Zbyt wiele żądań, spróbuj ponownie później." }
});

app.use(express.json());
app.use(limiter);
app.use(helmet());

app.use(
    cors({
            credentials: true,
            // origin: ORIGIN,
            origin: (origin, callback) => {
                if (!origin || origin.startsWith('http://192.168.') || origin.startsWith('http://localhost')) {
                    callback(null, true);
                } else {
                    callback(new Error('Nieautoryzowany dostęp z tego źródła.'));
                }
            },
            methods: ["OPTIONS", "GET", "POST", "PATCH", "DELETE"],
            allowedHeaders: ["Content-Type", "Authorization"]
    })
);

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
    token: {
        type: DataTypes.STRING,
        validate: { len: [100, 500] },
        allowNull: false,
        unique: true
    }
});

const UserProduct = sequelize.define("UserProduct", {});
User.belongsToMany(Product, { through: UserProduct });
Product.belongsToMany(User, { through: UserProduct });

sequelize.sync()
    .then(() => {
        console.log("Baza danych zaktualizowana");
    })
    .catch((err) => {
        console.error("Błąd podczas synchronizacji bazy danych:", err);
    });

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
        const blacklistedToken = await Blacklist.findOne({ where: { token } });
        if (blacklistedToken) {
            return res.status(401).json({ error: "Access token został unieważniony." });
        }

        const decoded = jwt.verify(token, ACCESS_TOKEN_KEY);
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
 *                 description: Nazwa użytkownika (5-20 znaków, bez spacji)
 *               email:
 *                 type: string
 *                 description: Adres email użytkownika
 *               password:
 *                 type: string
 *                 description: Hasło (8-20 znaków, minimum jedna cyfra i znak specjalny)
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

        if (username.length < 5 || username.length > 20 || username.includes(" ")) {
            return res.status(400).json({ error: "Niepoprawna nazwa użytkownika." });
        }

        if (email.length < 6 || email.length > 320 || !email.includes("@") || !email.includes(".") || email.includes(" ")) {
            return res.status(400).json({ error: "Niepoprawny email." });
        }

        const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,20}$/;
        if (!passwordRegex.test(password) || password.includes(" ")) {
            return res.status(400).json({ error: "Niepoprawne hasło." });
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

        const access_token_expiresIn = "00:00:00:30";
        const refresh_token_expiresIn = "00:01:00:00";
        const access_token = jwt.sign({ id: newUser.id, username: newUser.username }, ACCESS_TOKEN_KEY);
        const refresh_token = jwt.sign({ id: newUser.id, username: newUser.username }, REFRESH_TOKEN_KEY);

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
            where: { [Op.or]: [{ username: usernameOrEmail }, { email: usernameOrEmail }] }
        });

        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Nieprawidłowe dane logowania." });
        }

        const access_token_expiresIn = "00:00:00:10";
        const refresh_token_expiresIn = remember ? "07:00:00:00" : "00:01:00:00";
        const access_token = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_KEY);
        const refresh_token = jwt.sign({ id: user.id, username: user.username }, REFRESH_TOKEN_KEY);

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

app.post("/api/logout", jwtAuth, async (req, res) => {
    try {
        const { refresh_token } = req.body;
        if (!refresh_token) {
            return res.status(400).json({ error: "Brak refresh tokenu." });
        }
        const access_token = req.headers.authorization.split(" ")[1];

        await Blacklist.create({ token: access_token });
        await Blacklist.create({ token: refresh_token });

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
        console.log(refresh_token);
        const blacklistedRefreshToken = await Blacklist.findOne({ where: { token: refresh_token } });
        if (blacklistedRefreshToken) {
            return res.status(401).json({ error: "Refresh token został unieważniony." });
        }
        const refreshTokenDecoded = jwt.verify(refresh_token, REFRESH_TOKEN_KEY);
        const user = await User.findByPk(refreshTokenDecoded.id);
        if (!user) {
            return res.status(404).json({ error: "Użytkownik nie znaleziony." });
        }

        const access_token_expiresIn = "00:00:10:00";
        const refresh_token_expiresIn = "00:01:00:00";
        const access_token = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_KEY);
        const new_refresh_token = jwt.sign({ id: user.id, username: user.username }, REFRESH_TOKEN_KEY);
        
        res.status(200).json({ message: "Odświeżono tokeny.", username: user.username, email: user.email, access_token: access_token, refresh_token: new_refresh_token, expire_time: access_token_expiresIn.toString(), refresh_expire_time: refresh_token_expiresIn.toString() });
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

app.use((req, res) => {
    res.status(404).json({ error: "Nie znaleziono zasobu." });
});

app.listen(PORT, () => 
{
    console.log(`Serwer działa na ${ADDRESS}${PORT}`);
    console.log(`Dokumentacja API: ${ADDRESS}${PORT}${SWAGGER}`);
});