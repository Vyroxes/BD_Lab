import React, { Suspense, lazy } from 'react';
import { Route, Routes, Navigate, useLocation } from 'react-router-dom';
import createStore from 'react-auth-kit/createStore';
import AuthProvider from 'react-auth-kit';

import './App.css';

const Login = lazy(() => import('./components/Login'));
const Register = lazy(() => import('./components/Register'));
const Home = lazy(() => import('./components/Home'));
const Products = lazy(() => import('./components/Products'));
const Product = lazy(() => import('./components/Product'));
const Header = lazy(() => import('./components/Header'));
const Footer = lazy(() => import('./components/Footer'));

const store = createStore({
  authName:'access_token',
  authType:'cookie',
  cookieDomain: window.location.hostname,
  cookieSecure: true,
});

const App = () => {
  const location = useLocation();

  return (
    <AuthProvider store={store}>
      <Suspense>
        <div className='app'>
          {location.pathname !== '/login' && location.pathname !== '/register' && (<Header/>)}
          <Routes>
          <Route path="/login" element={<Login/>}/>
          <Route path="/register" element={<Register/>}/>
            <Route path="/login" element={<Login/>}/>
            <Route path="/register" element={<Register/>}/>
            <Route path="/home" element={<Home/>}/>
            <Route path="/products" element={<Products/>}/>
            <Route path="/product/:id" element={<Product/>}/>
            <Route path="*" element={<Navigate to="/home"/>}/>
          </Routes>
          {location.pathname !== '/login' && location.pathname !== '/register' && (<Footer/>)}
        </div>
      </Suspense>
    </AuthProvider>
  );
};

export default App
