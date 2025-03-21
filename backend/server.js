import express from "express";
import { Sequelize, DataTypes, Op } from "sequelize";
import cors from "cors";
import swaggerJsDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import dotenv from "dotenv";

dotenv.config({path: "../.env"});

const app = express();
const ADDRESS = process.env.ADDRESS;
const PORT = process.env.PORT;
const SWAGGER = process.env.SWAGGER;
const API_KEY = process.env.API_KEY;
const ORIGIN = process.env.ORIGIN;

app.use(express.json());
app.use(cors({ credentials: true, origin: ORIGIN }));

const sequelize = new Sequelize({
    dialect: "sqlite",
    storage: "products.db"
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

sequelize.sync();

const checkApiKey = (req, res, next) => 
{
    const apiKey = req.header("X-API-KEY");
    if (apiKey !== API_KEY) 
    {
        return res.status(403).json({ error: "Brak poprawnego klucza API" });
    }
    next();
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
app.get("/products", checkApiKey, async (req, res) => 
{
    const products = await Product.findAll();
    res.status(200).json(products);
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
app.get("/product/:id", checkApiKey, async (req, res) => 
{
    const product = await Product.findByPk(req.params.id);
    if (!product) 
    {
        return res.status(404).json({ message: "Brak produktu w bazie danych." });
    }
    res.status(200).json(product);
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
app.post("/add-product", checkApiKey, async (req, res) => 
{
    const { product } = req.body;
    if (!product || product.length < 3) 
    {
        return res.status(400).json({ error: "Nazwa produktu musi zawierać co najmniej 3 znaki." });
    }

    const existingProduct = await Product.findOne({ where: { product } });
    if (existingProduct) 
    {
        return res.status(409).json({ error: "Produkt o tej nazwie już istnieje w bazie danych." });
    }

    const newProduct = await Product.create({ product });
    res.status(201).json({ message: "Produkt dodany do bazy danych.", product: newProduct });
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
app.delete("/delete-product/:id", checkApiKey, async (req, res) => 
{
    const product = await Product.findByPk(req.params.id);
    if (!product) 
    {
        return res.status(404).json({ message: "Brak produktu w bazie danych." });
    }

    await product.destroy();
    res.status(200).json({ message: "Produkt został usunięty z bazy danych." });
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
app.patch("/edit-product/:id", checkApiKey, async (req, res) => 
{
    const { product } = req.body;
    const existingProduct = await Product.findByPk(req.params.id);

    if (!existingProduct) 
    {
        return res.status(404).json({ message: "Brak produktu w bazie danych." });
    }

    if (existingProduct.product == product) 
    {
        return res.status(409).json({ message: "Produkt ma już taką nazwę." });
    }

    if (product.length < 3) 
    {
        return res.status(400).json({ error: "Nazwa produktu musi zawierać co najmniej 3 znaki." });
    }

    const productWithSameName = await Product.findOne({
        where: {
            product: product,
            id: { [Op.ne]: req.params.id }
        }
    });

    if (productWithSameName) {
        return res.status(409).json({ message: "Produkt o tej nazwie już istnieje w bazie danych." });
    }

    existingProduct.product = product || existingProduct.product;
    await existingProduct.save();
    
    res.status(200).json({ message: "Produkt zaktualizowany w bazie danych.", product: existingProduct });
});

app.listen(PORT, () => 
{
    console.log(`Serwer działa na ${ADDRESS}${PORT}`);
    console.log(`Dokumentacja API: ${ADDRESS}${PORT}${SWAGGER}`);
});