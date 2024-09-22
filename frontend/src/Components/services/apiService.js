import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000/api',
    withCredentials: true,
});

export const getCsrfToken = async () => {
    try {
        await api.get('/sanctum/csrf-cookie');
    } catch (error) {
        console.error('Error fetching CSRF token', error);
    }
};

export const login = async (email, password) => {
    try {
        await getCsrfToken(); // Fetch CSRF token before making the login request
        const response = await api.post('/login', { email, password });
        console.log(response);
        return response.data;
    } catch (error) {
        throw error.response.data;
    }
};

export const sendResetLinkEmail = async (email) => {
    try{
        const response = await api.post('/forgot-password', { email });
        console.log(response);
        return response.data;
    } catch (error){
        throw error.response.data;
    }
};

export const setNewPassword = async({ email, password, password_confirmation, token }) => {
    const response = await api.post('/reset-password', {
        email,
        password,
        password_confirmation,
        token,
    });
    return response.data;
};

export default api;
