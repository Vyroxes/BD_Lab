import { Suspense, lazy } from 'react';
import { Route, Routes, Navigate } from 'react-router-dom';

import './App.css';

const Login = lazy(() => import('./components/Login'));
const Register = lazy(() => import('./components/Register'));
const AuthCallback = lazy(() => import('./components/AuthCallback'));
const Home = lazy(() => import('./components/Home'));
const Products = lazy(() => import('./components/Products'));
const Product = lazy(() => import('./components/Product'));
const Premium = lazy(() => import('./components/Premium'));
const User = lazy(() => import('./components/User'));

import ProtectedRoute from './components/ProtectedRoute';

function App() {
  return (
    <Suspense>
      <div className='app'>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/auth-callback" element={<AuthCallback />} />
          <Route path="/home" element={<ProtectedRoute><Home /></ProtectedRoute>} />
          <Route path="/products" element={<ProtectedRoute><Products /></ProtectedRoute>} />
          <Route path="/product/:id" element={<ProtectedRoute><Product /></ProtectedRoute>} />
          <Route path="/premium" element={<ProtectedRoute><Premium /></ProtectedRoute>} />
          <Route path="/users/:username" element={<ProtectedRoute><User /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    </Suspense>
  );
};

export default App