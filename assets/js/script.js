const themeToggler = document.getElementById('theme-toggle');
const darkModeIcon = document.getElementById('dark-mode-icon');
const lightModeIcon = document.getElementById('light-mode-icon');

function getUserPreference() {
  // Default to light if no preference is set
  return localStorage.getItem('theme') || 'light';
}

function saveUserPreference(userPreference) {
  localStorage.setItem('theme', userPreference);
}

function setAppliedMode(mode) {
  // Set the applied mode data attribute on <html>
  document.documentElement.dataset.appliedMode = mode;

  // Set the data-theme attribute on <html> to match the mode
  document.documentElement.setAttribute('data-theme', mode);

  // Toggle dark and light mode classes and icon visibility
  if (mode === 'dark') {
    document.documentElement.classList.add('dark-mode');
    document.documentElement.classList.remove('light-mode');
    darkModeIcon.style.display = 'inline';
    lightModeIcon.style.display = 'none';
  } else {
    document.documentElement.classList.add('light-mode');
    document.documentElement.classList.remove('dark-mode');
    darkModeIcon.style.display = 'none';
    lightModeIcon.style.display = 'inline';
  }
}

function toggleMode(userPreference) {
  return userPreference === 'light' ? 'dark' : 'light';
}

let userPreference = getUserPreference();
setAppliedMode(userPreference);

themeToggler.onclick = () => {
  const newUserPref = toggleMode(userPreference);
  userPreference = newUserPref;
  saveUserPreference(newUserPref);
  setAppliedMode(newUserPref);
};
