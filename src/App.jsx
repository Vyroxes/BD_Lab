import React, { Suspense, lazy, useEffect, useState } from 'react';
import { Route, Routes, Navigate, useLocation } from 'react-router-dom';
import { isAuthenticated } from './utils/Auth';

import './App.css';

const Login = lazy(() => import('./components/Login'));
const Register = lazy(() => import('./components/Register'));
const Home = lazy(() => import('./components/Home'));
const Products = lazy(() => import('./components/Products'));
const Product = lazy(() => import('./components/Product'));
const Premium = lazy(() => import('./components/Premium'));
const User = lazy(() => import('./components/User'));
const Header = lazy(() => import('./components/Header'));
const Footer = lazy(() => import('./components/Footer'));

const App = () => {
  const location = useLocation();

  const [authState, setAuthState] = useState(false);

  useEffect(() => {
    const checkAuth = async () => {
      const result = await isAuthenticated();
      setAuthState(result);
    };

    checkAuth();
  }, [location]);

  if (authState === null) {
    return null;
  }

  return (
    <Suspense>
      <div className='app'>
        {location.pathname !== '/login' && location.pathname !== '/register' && (<Header/>)}
        <Routes>
          <Route path="/login" element={<Login onLogin={() => setAuthState(true)}/>}/>
          <Route path="/register" element={<Register onLogin={() => setAuthState(true)}/>}/>
          <Route path="/home" element={authState ? <Home /> : <Navigate to="/login" />} />
          <Route path="/products" element={authState ? <Products/> : <Navigate to="/login" />}/>
          <Route path="/product/:id" element={authState ? <Product/> : <Navigate to="/login" />}/>
          <Route path="/premium" element={authState ? <Premium/> : <Navigate to="/login" />}/>
          <Route path="/users/:username" element={authState ? <User/> : <Navigate to="/login" />}/>
          <Route path="*" element={<Navigate to="/home"/>}/>
        </Routes>
        {location.pathname !== '/login' && location.pathname !== '/register' && (<Footer/>)}
      </div>
    </Suspense>
  );
};

export default App