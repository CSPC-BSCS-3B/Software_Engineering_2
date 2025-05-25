const signUpButton = document.getElementById("signUp");
const signInButton = document.getElementById("signIn");
const container = document.getElementById("container");

signUpButton.addEventListener("click", () => {
  container.classList.add("right-panel-active");
});

signInButton.addEventListener("click", () => {
  container.classList.remove("right-panel-active");
});

// Auto-fade flash messages after 5 seconds
document.addEventListener("DOMContentLoaded", function() {
  const flashMessages = document.querySelectorAll('.flash');
  
  flashMessages.forEach(function(flash) {
    setTimeout(function() {
      flash.classList.add('fade-out');
      
      // Remove the element completely after fade animation completes
      setTimeout(function() {
        if (flash.parentNode) {
          flash.parentNode.removeChild(flash);
        }
      }, 500); // Wait for fade animation to complete (0.5s)
    }, 5000); // Start fading after 5 seconds
  });

  // Initialize form validation
  initializeFormValidation();
});

function initializeFormValidation() {
  // Registration form validation
  const registerForm = document.getElementById('registerForm');
  const loginForm = document.getElementById('loginForm');
  
  if (registerForm) {
    setupRegistrationValidation();
  }
  
  if (loginForm) {
    setupLoginValidation();
  }
}

function setupRegistrationValidation() {
  const form = document.getElementById('registerForm');
  const submitButton = document.getElementById('signUpSubmit');
  
  // Form elements
  const username = document.getElementById('username');
  const firstName = document.getElementById('firstName');
  const middleName = document.getElementById('middleName');
  const lastName = document.getElementById('lastName');
  const email = document.getElementById('email');
  const password = document.getElementById('password');
  const confirmPassword = document.getElementById('confirmPassword');
  const noMiddleName = document.getElementById('cb');
  
  // Validation patterns
  const patterns = {
    username: /^[a-zA-Z0-9_]{3,30}$/,
    name: /^[a-zA-Z\s'-]{1,50}$/,
    email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    password: {
      minLength: /.{8,}/,
      uppercase: /[A-Z]/,
      lowercase: /[a-z]/,
      number: /\d/,
      special: /[!@#$%^&*(),.?":{}|<>]/
    }
  };
  
  // Real-time validation setup
  username.addEventListener('input', () => validateUsername());
  firstName.addEventListener('input', () => validateFirstName());
  middleName.addEventListener('input', () => validateMiddleName());
  lastName.addEventListener('input', () => validateLastName());
  email.addEventListener('input', () => validateEmail());
  password.addEventListener('input', () => validatePassword());
  confirmPassword.addEventListener('input', () => validateConfirmPassword());
  noMiddleName.addEventListener('change', () => validateMiddleName());
  
  // Validation functions
  function validateUsername() {
    const value = username.value.trim();
    const errorElement = document.getElementById('username-error');
    
    if (!value) {
      showError(errorElement, 'Username field cannot be empty.');
      return false;
    } else if (!patterns.username.test(value)) {
      showError(errorElement, 'Username must be 3-30 characters long and contain only letters, numbers, and underscores.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateFirstName() {
    const value = firstName.value.trim();
    const errorElement = document.getElementById('firstName-error');
    
    if (!value) {
      showError(errorElement, 'First Name field cannot be empty.');
      return false;
    } else if (!patterns.name.test(value)) {
      showError(errorElement, 'First name should contain only letters, spaces, hyphens, and apostrophes.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateMiddleName() {
    const value = middleName.value.trim();
    const errorElement = document.getElementById('middleName-error');
    const noMiddleNameChecked = noMiddleName.checked;
    
    if (noMiddleNameChecked && value) {
      showError(errorElement, 'I thought you have no middle name?');
      return false;
    } else if (!noMiddleNameChecked && !value) {
      showError(errorElement, 'Middle Name field cannot be empty.');
      return false;
    } else if (value && !patterns.name.test(value)) {
      showError(errorElement, 'Middle name should contain only letters, spaces, hyphens, and apostrophes.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateLastName() {
    const value = lastName.value.trim();
    const errorElement = document.getElementById('lastName-error');
    
    if (!value) {
      showError(errorElement, 'Last Name field cannot be empty.');
      return false;
    } else if (!patterns.name.test(value)) {
      showError(errorElement, 'Last name should contain only letters, spaces, hyphens, and apostrophes.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateEmail() {
    const value = email.value.trim();
    const errorElement = document.getElementById('email-error');
    
    if (!value) {
      showError(errorElement, 'Email field cannot be empty.');
      return false;
    } else if (!patterns.email.test(value)) {
      showError(errorElement, 'Please enter a valid email address.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validatePassword() {
    const value = password.value;
    const errorElement = document.getElementById('password-error');
    const requirements = document.getElementById('passwordRequirements');
    
    if (!value) {
      showError(errorElement, 'Password field cannot be empty.');
      hidePasswordRequirements();
      return false;
    }
    
    showPasswordRequirements();
    updatePasswordRequirements(value);
    
    if (!patterns.password.minLength.test(value)) {
      showError(errorElement, 'Password must be at least 8 characters long.');
      return false;
    } else if (!patterns.password.uppercase.test(value)) {
      showError(errorElement, 'Password must contain at least one uppercase letter.');
      return false;
    } else if (!patterns.password.lowercase.test(value)) {
      showError(errorElement, 'Password must contain at least one lowercase letter.');
      return false;
    } else if (!patterns.password.number.test(value)) {
      showError(errorElement, 'Password must contain at least one number.');
      return false;
    } else if (!patterns.password.special.test(value)) {
      showError(errorElement, 'Password must contain at least one special character.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateConfirmPassword() {
    const value = confirmPassword.value;
    const passwordValue = password.value;
    const errorElement = document.getElementById('confirmPassword-error');
    
    if (!value) {
      showError(errorElement, 'Confirm Password field cannot be empty.');
      return false;
    } else if (value !== passwordValue) {
      showError(errorElement, 'Passwords do not match.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function updatePasswordRequirements(passwordValue) {
    const requirements = {
      length: patterns.password.minLength.test(passwordValue),
      uppercase: patterns.password.uppercase.test(passwordValue),
      lowercase: patterns.password.lowercase.test(passwordValue),
      number: patterns.password.number.test(passwordValue),
      special: patterns.password.special.test(passwordValue)
    };
    
    Object.keys(requirements).forEach(req => {
      const element = document.getElementById(req);
      if (element) {
        element.style.color = requirements[req] ? '#155724' : '#721c24';
        element.style.fontWeight = requirements[req] ? 'bold' : 'normal';
      }
    });
  }
  
  function showPasswordRequirements() {
    const requirements = document.getElementById('passwordRequirements');
    if (requirements) {
      requirements.style.display = 'block';
    }
  }
  
  function hidePasswordRequirements() {
    const requirements = document.getElementById('passwordRequirements');
    if (requirements) {
      requirements.style.display = 'none';
    }
  }
  
  function showError(element, message) {
    if (element) {
      element.textContent = message;
      element.style.display = 'block';
      element.style.color = '#721c24';
    }
  }
  
  function clearError(element) {
    if (element) {
      element.textContent = '';
      element.style.display = 'none';
    }
  }
  
  // Check if all fields are valid and enable/disable submit button
  function checkFormValidity() {
    const isValid = validateUsername() && 
                   validateFirstName() && 
                   validateMiddleName() && 
                   validateLastName() && 
                   validateEmail() && 
                   validatePassword() && 
                   validateConfirmPassword();
    
    submitButton.disabled = !isValid;
    submitButton.style.opacity = isValid ? '1' : '0.6';
    submitButton.style.cursor = isValid ? 'pointer' : 'not-allowed';
    
    return isValid;
  }
  
  // Add event listeners to check validity on every input
  [username, firstName, middleName, lastName, email, password, confirmPassword].forEach(input => {
    input.addEventListener('input', checkFormValidity);
    input.addEventListener('blur', checkFormValidity);
  });
  
  noMiddleName.addEventListener('change', checkFormValidity);
  
  // Form submission with final validation
  form.addEventListener('submit', function(event) {
    event.preventDefault();
    
    if (!checkFormValidity()) {
      alert('Please fix all form errors before submitting.');
      return false;
    }
    
    // Sanitize inputs before submission (basic XSS prevention)
    [username, firstName, middleName, lastName, email].forEach(input => {
      input.value = sanitizeInput(input.value);
    });
    
    // Submit the form
    form.submit();
  });
  
  // Initial validation check
  setTimeout(checkFormValidity, 100);
}

function setupLoginValidation() {
  const form = document.getElementById('loginForm');
  const submitButton = document.getElementById('signInSubmit');
  const username = document.getElementById('loginUsername');
  const password = document.getElementById('loginPassword');
  
  function validateLoginUsername() {
    const value = username.value.trim();
    const errorElement = document.getElementById('loginUsername-error');
    
    if (!value) {
      showError(errorElement, 'Username field cannot be empty.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function validateLoginPassword() {
    const value = password.value;
    const errorElement = document.getElementById('loginPassword-error');
    
    if (!value) {
      showError(errorElement, 'Password field cannot be empty.');
      return false;
    } else {
      clearError(errorElement);
      return true;
    }
  }
  
  function showError(element, message) {
    if (element) {
      element.textContent = message;
      element.style.display = 'block';
      element.style.color = '#721c24';
    }
  }
  
  function clearError(element) {
    if (element) {
      element.textContent = '';
      element.style.display = 'none';
    }
  }
  
  // Real-time validation
  username.addEventListener('input', validateLoginUsername);
  password.addEventListener('input', validateLoginPassword);
  
  // Form submission validation
  form.addEventListener('submit', function(event) {
    if (!validateLoginUsername() || !validateLoginPassword()) {
      event.preventDefault();
      return false;
    }
    
    // Sanitize username input
    username.value = sanitizeInput(username.value);
  });
}

// Basic XSS prevention function
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}
