// Application configuration

// SECURITY: All secrets must be loaded from environment variables or secure secret management systems.
// Hard-coded credentials expose the application to credential theft and unauthorized access.
module.exports = {
  // Cookie / session signing
  COOKIE_SECRET: process.env.COOKIE_SECRET || (() => { throw new Error('COOKIE_SECRET environment variable is required'); })(),

  // JWT
  JWT_SECRET: process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET environment variable is required'); })(),

  // Database
  DB_HOST: process.env.DB_HOST || 'localhost',
  DB_USER: process.env.DB_USER || (() => { throw new Error('DB_USER environment variable is required'); })(),
  DB_PASSWORD: process.env.DB_PASSWORD || (() => { throw new Error('DB_PASSWORD environment variable is required'); })(),
  DB_NAME: process.env.DB_NAME || 'production',

  // Cloud / 3rd-party
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || (() => { throw new Error('AWS_ACCESS_KEY_ID environment variable is required'); })(),
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || (() => { throw new Error('AWS_SECRET_ACCESS_KEY environment variable is required'); })(),
  STRIPE_KEY: process.env.STRIPE_KEY || (() => { throw new Error('STRIPE_KEY environment variable is required'); })(),
  SENDGRID_API_KEY: process.env.SENDGRID_API_KEY || (() => { throw new Error('SENDGRID_API_KEY environment variable is required'); })(),
  GITHUB_PAT: process.env.GITHUB_PAT || (() => { throw new Error('GITHUB_PAT environment variable is required'); })(),
  SLACK_TOKEN: process.env.SLACK_TOKEN || (() => { throw new Error('SLACK_TOKEN environment variable is required'); })(),

  // Misc
  ADMIN_USERNAME: process.env.ADMIN_USERNAME || (() => { throw new Error('ADMIN_USERNAME environment variable is required'); })(),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || (() => { throw new Error('ADMIN_PASSWORD environment variable is required'); })(),

  DEBUG: process.env.DEBUG === 'true',
};