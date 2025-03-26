import React, { useEffect } from 'react';
import useIsAuthenticated from 'react-auth-kit/hooks/useIsAuthenticated'
import { useNavigate } from "react-router-dom";

import './Home.css';

const Home = () => {
    const isAuthenticated = useIsAuthenticated();
    const navigate = useNavigate();

    useEffect(() => 
    {
        if (!isAuthenticated) 
        {
            navigate('/login');
        }
    }, [isAuthenticated, navigate]);

    return (
        <div className="home-container">
            <h1>Strona główna</h1>
            <h3>Strona stworzona na potrzebny laboratorium z przedmiotu backend development</h3>
        </div>
    );
};

export default Home;