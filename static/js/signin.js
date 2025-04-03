// Regular expression patterns for validation
const USERNAME_PATTERN = /^[a-zA-Z0-9]{1,20}$/;
const PASSWORD_PATTERN = /^[\x21-\x7E]{8,}$/;

// Variables to track state
let loginAttemptInProgress = false;
let registerAttemptInProgress = false;

// Helper functions to set error and valid states
const setError = (input, message) => {
  input.classList.add("is-invalid");
  input.classList.remove("is-valid");
  const feedback = input.parentElement.querySelector(".invalid-feedback");
  if (feedback) {
    feedback.textContent = message;
  }
};

const setValid = (input) => {
  input.classList.add("is-valid");
  input.classList.remove("is-invalid");
};

// Validates password
function validatePassword(id) {
  console.log("Validating password for", id);
  const password = document.getElementById(id);
  if (!password) {
    console.error("Password element not found:", id);
    return false;
  }
  
  if (!PASSWORD_PATTERN.test(password.value)) {
    setError(password, "Password must be at least 8 characters with no spaces.");
    return false;
  }

  setValid(password);
  return true;
}

// Username validation
function validateUsername(id) {
  console.log("Validating username for", id);
  const username = document.getElementById(id);
  if (!username) {
    console.error("Username element not found:", id);
    return false;
  }
  
  if (!USERNAME_PATTERN.test(username.value)) {
    setError(username, "Username must be alphanumeric and at most 20 characters.");
    return false;
  }
  setValid(username);
  return true;
}

// Display name validation
function validateDisplayName(id) {
  console.log("Validating display name for", id);
  const displayName = document.getElementById(id);
  if (!displayName) {
    console.error("Display name element not found:", id);
    return false;
  }
  
  if (!displayName.value.trim()) {
    setError(displayName, "Display name cannot be empty.");
    return false;
  }
  setValid(displayName);
  return true;
}

// Handle login form submission
function validateLoginForm(event) {
  event.preventDefault();
  console.log("Login form submission attempted");
  
  // Get form elements
  const username = document.getElementById("loginUsername");
  const password = document.getElementById("loginPassword");
  
  if (!username || !password) {
    console.error("Login form elements not found", {username, password});
    return false;
  }
  
  // Validate fields
  const isUsernameValid = validateUsername("loginUsername");
  const isPasswordValid = validatePassword("loginPassword");
  
  if (!isUsernameValid || !isPasswordValid) {
    console.log("Login validation failed");
    return false;
  }
  
  console.log("Login validation passed, sending request");
  
  // Prepare login data
  const formData = {
    username: username.value,
    password: password.value
  };
  
  // Create request
  const request = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(formData)
  };
  
  console.log("Sending login request");
  
  // Send request
  fetch("/login", request)
    .then(response => {
      console.log("Login response received", response);
      
      if (response.ok) {
        return response.json().then(data => {
          console.log("Login successful", data);
          alert("Login successful! Welcome back, " + data.displayName);
          window.location.href = "/";
          return true;
        });
      } else {
        return response.json().then(data => {
          console.log("Login failed", data);
          alert("Login failed: " + data.message);
          return false;
        }).catch(err => {
          console.error("Error parsing login response", err);
          alert("Login failed with an unknown error. Please try again.");
          return false;
        });
      }
    })
    .catch(error => {
      console.error("Network error during login", error);
      alert("A network error occurred. Please check your connection and try again.");
      return false;
    });
}

// Handle registration form submission
function validateRegisterForm(event) {
  event.preventDefault();
  console.log("Register form submission attempted");
  
  // Get form elements
  const username = document.getElementById("username");
  const password = document.getElementById("password");
  const displayName = document.getElementById("displayName");
  
  if (!username || !password || !displayName) {
    console.error("Register form elements not found", {username, password, displayName});
    return false;
  }
  
  // Validate fields
  const isUsernameValid = validateUsername("username");
  const isPasswordValid = validatePassword("password");
  const isDisplayNameValid = validateDisplayName("displayName");
  
  if (!isUsernameValid || !isPasswordValid || !isDisplayNameValid) {
    console.log("Register validation failed");
    return false;
  }
  
  console.log("Register validation passed, sending request");
  
  // Prepare registration data
  const formData = {
    username: username.value,
    password: password.value,
    displayName: displayName.value
  };
  
  // Create request
  const request = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(formData)
  };
  
  console.log("Sending register request", formData);
  
  // Send request
  fetch("/register", request)
    .then(response => {
      console.log("Register response received", response);
      
      if (response.ok) {
        console.log("Registration successful");
        alert("Registration successful! You can now log in.");
        
        // Clear the form
        document.getElementById("registerForm").reset();
        
        // Close modal if using Bootstrap modals
        if (typeof bootstrap !== 'undefined') {
          const registerModal = bootstrap.Modal.getInstance(document.getElementById('registerModal'));
          if (registerModal) {
            registerModal.hide();
          }
        }
        
        return true;
      } else {
        return response.json().then(data => {
          console.log("Registration failed", data);
          alert("Registration failed: " + data.message);
          return false;
        }).catch(err => {
          console.error("Error parsing registration response", err);
          alert("Registration failed with an unknown error. Please try again.");
          return false;
        });
      }
    })
    .catch(error => {
      console.error("Network error during registration", error);
      alert("A network error occurred. Please check your connection and try again.");
      return false;
    });
}

// Attach event listeners when DOM is ready
function attachEventListeners() {
  console.log("Attaching event listeners");
  
  // Register form submission
  const registerForm = document.getElementById("registerForm");
  if (registerForm) {
    console.log("Register form found, attaching event listener");
    registerForm.addEventListener("submit", validateRegisterForm);
  } else {
    console.error("Register form not found");
  }
  
  // Login form submission
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    console.log("Login form found, attaching event listener");
    loginForm.addEventListener("submit", validateLoginForm);
  } else {
    console.error("Login form not found");
  }
  
  console.log("Event listeners attached");
}

// Initialize when DOM is ready
function onReady(callback) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", callback);
  } else {
    callback();
  }
}

// Start the application
console.log("Script loaded, waiting for DOM ready");
onReady(attachEventListeners);