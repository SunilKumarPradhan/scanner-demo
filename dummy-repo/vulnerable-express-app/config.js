// Application configuration

module.exports = {
  // Cookie / session signing
  COOKIE_SECRET: process.env.COOKIE_SECRET,

  // JWT
  JWT_SECRET: process.env.JWT_SECRET,

  // Database
  DB_HOST: process.env.DB_HOST || 'localhost',
  DB_USER: process.env.DB_USER,
  DB_PASSWORD: process.env.DB_PASSWORD,
  DB_NAME: process.env.DB_NAME || 'development',

  // Cloud / 3rd-party
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
  STRIPE_KEY: process.env.STRIPE_KEY,
  SENDGRID_API_KEY: process.env.SENDGRID_API_KEY,
  GITHUB_PAT: process.env.GITHUB_PAT,
  SLACK_TOKEN: process.env.SLACK_TOKEN,

  // Misc
  ADMIN_USERNAME: process.env.ADMIN_USERNAME,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,

  DEBUG: process.env.DEBUG === 'true',
};