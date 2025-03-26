import express from "express";
import { Sequelize, DataTypes, Op } from "sequelize";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import swaggerJsDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import dotenv from "dotenv";

dotenv.config({path: "../.env"});

const app = express();
const ADDRESS = process.env.ADDRESS;
const PORT = process.env.PORT;
const SWAGGER = process.env.SWAGGER;
const SECRET_KEY = process.env.SECRET_KEY;
const ORIGIN = process.env.ORIGIN;

app.use(express.json());
app.use(cors({ credentials: true, origin: ORIGIN }));

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
        allowNull: false,
        unique: true
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
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
        allowNull: false
    }
});

const UserProduct = sequelize.define("UserProduct", {});
User.belongsToMany(Product, { through: UserProduct });
Product.belongsToMany(User, { through: UserProduct });

sequelize.sync();

const jwtAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: "Brak tokenu autoryzacyjnego." });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ error: "Brak tokenu autoryzacyjnego." });
    }

    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Niepoprawny token." });
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
        servers: [{ url: `${ADDRESS}${PORT}` }]
    },
    apis: ["./server.js"]
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use(SWAGGER, swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Wszystkie pola są wymagane." });
    }

    if (username.length < 5 || username.length > 20 || username.includes(" ")) {
        return res.status(400).json({ error: "Niepoprawna nazwa użytkownika." });
    }

    if (email.length < 6 || email.length > 320 || !email.includes("@") || !email.includes(".") || email.includes(" ")) {
        return res.status(400).json({ error: "Niepoprawny email." });
    }

    const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,20}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ error: "Niepoprawne hasło." });
    }

    const existingUser = await User.findOne({ where: { [Op.or]: [{ username }, { email }] } });
    if (existingUser) {
        return res.status(409).json({ error: "Nazwa użytkownika lub email jest już zajęty." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({ username, email, password: hashedPassword });
    res.status(201).json({ message: "Rejestracja zakończona sukcesem.", user: newUser });
});

app.post("/login", async (req, res) => {
    const { usernameOrEmail, password, remember } = req.body;

    if (!usernameOrEmail || !password) {
        return res.status(400).json({ error: "Wszystkie pola są wymagane." });
    }

    const user = await User.findOne({
        where: { [Op.or]: [{ username: usernameOrEmail }, { email: usernameOrEmail }] }
    });

    if (!user) {
        return res.status(404).json({ error: "Nieprawidłowe dane logowania." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).json({ error: "Nieprawidłowe dane logowania." });
    }

    const expiresIn = remember ? "7d" : "5s";
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn });

    res.status(200).json({ message: "Zalogowano pomyślnie.", access_token: token, username: user.username });
});

/**
 * @swagger
 * /products:
 *   get:
 *     summary: Pobierz wszystkie produkty
 *     parameters:
 *       - name: X-API-KEY
 *         in: header
 *         required: true
 *         description: Klucz API
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Lista produktów
 */
app.get("/products", jwtAuth, async (req, res) => 
{
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const products = await user.getProducts();
        res.status(200).json(products);
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /product/{id}:
 *   get:
 *     summary: Pobierz produkt po ID
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID produktu
 *         schema:
 *           type: integer
 *       - name: X-API-KEY
 *         in: header
 *         required: true
 *         description: Klucz API
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Produkt znaleziony
 *       404:
 *         description: Produkt nie znaleziony
 */
app.get("/product/:id", jwtAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ message: "Nie znaleziono użytkownika." });
        }

        const products = await user.getProducts({ where: { id: req.params.id } });
        if (!products || products.length === 0) {
            return res.status(404).json({ message: "Brak produktu w bazie danych." });
        }

        res.status(200).json(products[0]);
    } catch (error) {
        res.status(500).json({ message: "Wystąpił błąd serwera." });
    }
});


/**
 * @swagger
 * /add-product:
 *   post:
 *     summary: Dodaj nowy produkt
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
 *       - name: X-API-KEY
 *         in: header
 *         required: true
 *         description: Klucz API
 *         schema:
 *           type: string
 *     responses:
 *       201:
 *         description: Produkt dodany
 *       400:
 *         description: Za krótka nazwa produktu
 *       409:
 *         description: Produkt już istnieje
 */
app.post("/add-product", jwtAuth, async (req, res) => {
    try {
        const { product } = req.body;

        if (!product || product.length < 3) {
            return res.status(400).json({ error: "Nazwa produktu musi zawierać co najmniej 3 znaki." });
        }

        let existingProduct = await Product.findOne({ where: { product } });

        if (!existingProduct) {
            existingProduct = await Product.create({ product });
        }

        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const hasProduct = await user.hasProduct(existingProduct);
        if (hasProduct) {
            return res.status(409).json({ error: "Produkt już jest przypisany do użytkownika." });
        }

        await user.addProduct(existingProduct);

        res.status(201).json({ message: "Produkt dodany do użytkownika.", product: existingProduct });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /delete-product/{id}:
 *   delete:
 *     summary: Usuń produkt
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID produktu
 *         schema:
 *           type: integer
 *       - name: X-API-KEY
 *         in: header
 *         required: true
 *         description: Klucz API
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Produkt usunięty
 *       404:
 *         description: Produkt nie znaleziony
 */
app.delete("/delete-product/:id", jwtAuth, async (req, res) => {
    try {
        const { id } = req.params;

        const user = await User.findByPk(req.user.id, { include: Product });

        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const product = await Product.findByPk(id);
        if (!product) {
            return res.status(404).json({ message: "Brak produktu w bazie danych." });
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

        res.status(200).json({ message: "Produkt usunięty z Twojej listy." });
    } catch (error) {
        res.status(500).json({ error: "Wystąpił błąd serwera." });
    }
});

/**
 * @swagger
 * /edit-product/{id}:
 *   patch:
 *     summary: Edytuj produkt
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
 *       - name: X-API-KEY
 *         in: header
 *         required: true
 *         description: Klucz API
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Produkt zaktualizowany
 *       400:
 *         description: Za krótka nazwa produktu
 *       404:
 *         description: Produkt nie znaleziony
 *       409:
 *         description: Produkt ma już taką nazwę
 */
app.patch("/edit-product/:id", jwtAuth, async (req, res) => {
    try {
        const { product } = req.body;
        const { id } = req.params;

        const user = await User.findByPk(req.user.id, { include: Product });

        if (!user) {
            return res.status(404).json({ error: "Nie znaleziono użytkownika." });
        }

        const existingProduct = await Product.findByPk(id);
        if (!existingProduct) {
            return res.status(404).json({ message: "Brak produktu w bazie danych." });
        }

        const hasProduct = await user.hasProduct(existingProduct);
        if (!hasProduct) {
            return res.status(403).json({ message: "Nie masz dostępu do tego produktu." });
        }

        if (existingProduct.product === product) {
            return res.status(409).json({ message: "Produkt ma już taką nazwę." });
        }

        if (product.length < 3) {
            return res.status(400).json({ error: "Nazwa produktu musi zawierać co najmniej 3 znaki." });
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

app.listen(PORT, () => 
{
    console.log(`Serwer działa na ${ADDRESS}${PORT}`);
    console.log(`Dokumentacja API: ${ADDRESS}${PORT}${SWAGGER}`);
});