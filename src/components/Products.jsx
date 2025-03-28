import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated';
import useAuthHeader from 'react-auth-kit/hooks/useAuthHeader';
import axios from 'axios';

import './Products.css';

const Products = () => {
    const isAuthenticated = useIsAuthenticated();
    const authHeader = useAuthHeader();
    const navigate = useNavigate();

    useEffect(() => 
    {
        if (!isAuthenticated) 
        {
            navigate('/login');
        }
        else
        {
            fetchProducts();
        }
    }, [isAuthenticated, navigate]);

    const [products, setProducts] = useState("");
    const [loading, setLoading] = useState(true);
    const [product, setProduct] = useState("");

    const fetchProducts = async () => {
        try 
        {
            const response = await axios.get(`/api/products`, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });

            if (response.status == 200)
            {
                setProducts(response.data);
                setLoading(false);
            }
        } 
        catch (error) 
        {
            console.error('Błąd podczas pobierania danych produktów: ', error);
        }
    };

    const addProduct = async () => {
        try 
        {
            const response = await axios.post(`/api/add-product`, {
                product: product
            }, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });

            if (response.status == 201)
            {
                fetchProducts();
                setProduct("");
            }
        } 
        catch (error) 
        {
            console.error('Błąd podczas dodawania produktu: ', error);
        }
    };

    const removeProduct = async (id) => {
        try {
            const response = await axios.delete(`/api/delete-product/${id}`, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });
            
            if (response.status === 200)
            {
                fetchProducts();
            }
        }
        catch (error)
        {
            console.error('Błąd podczas usuwania produktu: ', error);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        await addProduct();
    };

    if (loading) {
        return;
    }

    return (
        <div className='products-container'>
            <h1>Produkty</h1>
            {products.length == 0 && "Brak produktów w bazie danych"}
            {products.length > 0 && (
                <div className="products-list">
                    {products.length > 0 && products.map(prod => (
                        <div className="products-list-product" key={prod.id}>
                            <a>{prod.product}</a>
                            <div className='products-list-buttons'>
                                <button onClick={() => navigate(`/product/${prod.id}`)}>Edytuj</button>
                                <button onClick={() => removeProduct(prod.id)}>Usuń</button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
            <form className="product-add-form" onSubmit={handleSubmit}>
                <label>Nazwa produktu:
                    <input
                        type="text"
                        id="product"
                        name="product"
                        value={product}
                        onChange={(e) => setProduct(e.target.value)}
                        required
                        minLength={3}
                        maxLength={20}
                        >
                    </input>
                </label>
                <div>
                    <button type="submit">Dodaj produkt</button>
                </div>
            </form>
        </div>
    );
};

export default Products;