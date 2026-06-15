require('dotenv').config();
const app = require('./src/app');
const { connectDB } = require('./src/config/database');

const PORT = process.env.PORT || 3001;

connectDB()
  .then(() => app.listen(PORT, () => console.log(`[auth-service] :${PORT}`)))
  .catch(err => { console.error(err); process.exit(1); });