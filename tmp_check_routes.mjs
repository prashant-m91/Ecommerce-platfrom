(async () => {
  try {
    await import('./routes/admin.route.js');
    await import('./routes/order.route.js');
    console.log('Backend admin/order import check passed');
  } catch (err) {
    console.error('Import check failed:', err);
    process.exit(2);
  }
})();
