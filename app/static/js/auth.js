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
});
