import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated';
import useAuthHeader from 'react-auth-kit/hooks/useAuthHeader';
import axios from 'axios';

import './Product.css';

const Product = () => {
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
            fetchProduct();
        }
    }, [isAuthenticated, navigate]);

    const [loading, setLoading] = useState(true);
    const [productName, setProductName] = useState("");

    const { id } = useParams();

    const fetchProduct = async () => {
        try 
        {
            const response = await axios.get(`/api/product/${id}`, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });

            if (response.status == 200)
            {
                setProductName(response.data.product);
                setLoading(false);
            }
        } 
        catch (error) 
        {
            console.error('Błąd podczas pobierania danych produktu: ', error);
        }
    };

    const editProduct = async () => {
        try 
        {
            const response = await axios.patch(`/api/edit-product/${id}`, {
                product: productName
            }, {
                headers: {
                    'Authorization': authHeader
                },
                withCredentials: true
            });

            if (response.status == 200)
            {
                navigate("/products");
            }
        } 
        catch (error) 
        {
            console.error('Błąd podczas edytowania produktu: ', error);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        await editProduct();
    };

    if(loading) {
        return;
    }

    return (
        <div className='product-container'>
            <h1>Edycja produktu</h1>
            <form className="product-form" onSubmit={handleSubmit}>
                <label>Nazwa produktu:
                    <input 
                        type="text"
                        id="product"
                        name="product"
                        value={productName}
                        onChange={(e) => setProductName(e.target.value)}
                        required
                        minLength={3}
                    >
                    </input>
                </label>
                <div className='product-form-buttons'>
                    <button type="submit">Zmień nazwę</button>
                    <button type="button" onClick={() => navigate("/products")}>Anuluj</button>
                </div>
            </form>
        </div>
    );
};

export default Product