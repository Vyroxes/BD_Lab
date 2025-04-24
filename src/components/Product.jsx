import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { authAxios } from '../utils/Auth';

import './Product.css';

const Product = () => {
    const navigate = useNavigate();

    useEffect(() => {
        fetchProduct();
    }, []);

    const [loading, setLoading] = useState(true);
    const [productName, setProductName] = useState("");

    const { id } = useParams();

    const apiUrl = import.meta.env.VITE_API_URL;

    const fetchProduct = async () => {
        try 
        {
            const response = await authAxios.get(`${apiUrl}/api/product/${id}`);

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
            const response = await authAxios.patch(`${apiUrl}/api/edit-product/${id}`, {
                product: productName
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