// Bangun ulang CSS setelah mengubah kelas Tailwind di dashboard.html:
//   cd mirage-engine/static && npx tailwindcss@3 -c tailwind.config.js -i in.css -o vendor/tailwind.css --minify
module.exports = { content: ['../templates/dashboard.html'], theme: { extend: {} }, plugins: [] };
