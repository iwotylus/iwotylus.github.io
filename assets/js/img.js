const overlay = document.querySelector('.overlay');
const container = document.querySelector('.container');
const blogImages = document.querySelectorAll('.blog-img');

let clonedImg = null;
let isClosing = false;
let imageLoaded = false;

blogImages.forEach((img) => {
  img.addEventListener('click', (event) => {
    imageLoaded = false;
    if (isClosing) return;

    setTimeout(() => {
      container.classList.add('container-show');
    }, 50);

    container.innerHTML = '';

    clonedImg = img.cloneNode(true);

    container.appendChild(clonedImg).classList.add('show');

    overlay.style.display = 'block';

    setTimeout(() => {
      imageLoaded = true;
    }, 400);

    event.stopPropagation();
  });
});

overlay.addEventListener('click', (event) => {
  if (isClosing || !imageLoaded) return;

  isClosing = true;

  const existingImg = container.querySelector('img');

  if (existingImg) {
    existingImg.classList.remove('show');
    existingImg.classList.add('close');
  }

  container.classList.remove('container-show');

  setTimeout(() => {
    container.innerHTML = '';
    overlay.style.display = 'none';

    isClosing = false;
  }, 200); // Add a delay to allow the "close" animation to complete (adjust the time as needed)
});
