(async () => {
  try {
    await import('./middleware/auth.middleware.js');
    await import('./controllers/cart.controller.js');
    await import('./routes/auth.route.js');
    console.log('Import check passed');
  } catch (err) {
    console.error('Import check failed:', err);
    process.exit(2);
  }
})();
