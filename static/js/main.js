// Main JavaScript file for User Management System

// Check if user is logged in
function checkAuth() {
    const token = localStorage.getItem('access_token');
    const currentPath = window.location.pathname;
    
    // Skip auth check for login and password reset pages
    const publicPaths = ['/login', '/forgot-password', '/reset-password'];
    const isPublicPath = publicPaths.some(path => currentPath.startsWith(path));
    
    if (!token && !isPublicPath) {
        // Clear any stale data
        localStorage.removeItem('user_id');
        localStorage.removeItem('username');
        localStorage.removeItem('roles');
        
        // Redirect to login
        window.location.href = '/login';
        return false;
    }
    
    // Set cookie if it doesn't exist (to ensure server-side auth works)
    if (token && !document.cookie.includes('access_token=')) {
        document.cookie = `access_token=Bearer ${token}; path=/; max-age=1800; SameSite=Lax`;
    }
    
    return true;
}

// Add auth token to all fetch requests
function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('access_token');
    
    if (!options.headers) {
        options.headers = {};
    }
    
    if (token) {
        options.headers['Authorization'] = `Bearer ${token}`;
    }
    
    return fetch(url, options)
        .then(response => {
            // If we get a 401 Unauthorized, redirect to login
            if (response.status === 401) {
                // Only redirect if this is an API call, not a page load
                if (url.startsWith('/api/')) {
                    logout();
                    throw new Error('Authentication failed. Please log in again.');
                }
            }
            return response;
        });
}

// Handle logout
function logout() {
    // Clear localStorage
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('username');
    localStorage.removeItem('roles');
    
    // Use the server-side logout endpoint to clear cookies
    window.location.href = '/logout';
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Check if user has a specific role
function hasRole(role) {
    const roles = JSON.parse(localStorage.getItem('roles') || '[]');
    return roles.includes(role);
}

// Show notification
function showNotification(message, type = 'success') {
    const container = document.createElement('div');
    container.className = `toast align-items-center text-white bg-${type} border-0 position-fixed top-0 end-0 m-3`;
    container.setAttribute('role', 'alert');
    container.setAttribute('aria-live', 'assertive');
    container.setAttribute('aria-atomic', 'true');
    
    const flexContainer = document.createElement('div');
    flexContainer.className = 'd-flex';
    
    const body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = message;
    
    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'btn-close btn-close-white me-2 m-auto';
    closeButton.setAttribute('data-bs-dismiss', 'toast');
    closeButton.setAttribute('aria-label', 'Close');
    
    flexContainer.appendChild(body);
    flexContainer.appendChild(closeButton);
    container.appendChild(flexContainer);
    
    document.body.appendChild(container);
    
    const toast = new bootstrap.Toast(container, { delay: 5000 });
    toast.show();
    
    // Remove from DOM after hiding
    container.addEventListener('hidden.bs.toast', function () {
        document.body.removeChild(container);
    });
}

// Initialize tooltips and popovers
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication
    if (!checkAuth()) {
        return; // Stop initialization if not authenticated
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Add event listener to logout button
    const logoutBtn = document.querySelector('a[href="/logout"]');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            logout();
        });
    }
    
    // Check token validity
    validateToken();
});

// Service flag toggle function
async function toggleServiceFlag(flagId) {
    try {
        const response = await fetchWithAuth(`/api/service-flags/${flagId}/toggle`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            return await response.json();
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to toggle service flag');
        }
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Get current user info
async function getCurrentUser() {
    try {
        const response = await fetchWithAuth('/api/me');
        
        if (response.ok) {
            return await response.json();
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get user info');
        }
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Validate token
async function validateToken() {
    // Skip validation for login and public pages
    const currentPath = window.location.pathname;
    const publicPaths = ['/login', '/forgot-password', '/reset-password'];
    const isPublicPath = publicPaths.some(path => currentPath.startsWith(path));
    
    if (isPublicPath) {
        return true;
    }
    
    try {
        const response = await fetchWithAuth('/api/me');
        
        if (response.ok) {
            // Token is valid
            return true;
        } else if (response.status === 401) {
            // Token is invalid or expired
            console.log('Session expired. Redirecting to login...');
            logout();
            return false;
        }
    } catch (error) {
        console.error('Error validating token:', error);
        // If there's a network error, we'll assume the token is still valid
        // to prevent unnecessary logouts
        return true;
    }
}