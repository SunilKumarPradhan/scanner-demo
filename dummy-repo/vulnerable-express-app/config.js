// VULNERABILITY (CWE-798): hardcoded credentials in source

module.exports = {
  // Cookie / session signing
  COOKIE_SECRET: 'cookie-secret-do-not-share',

  // JWT
  JWT_SECRET: 'super-jwt-secret-12345',

  // Database
  DB_HOST: 'prod-db.internal.example.com',
  DB_USER: 'root',
  DB_PASSWORD: 'r00t-Pa$$w0rd',
  DB_NAME: 'production',

  // Cloud / 3rd-party
  AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  STRIPE_KEY: 'sk_demo_4eC39HqLyjWDarjtT1zdp7dc',
  SENDGRID_API_KEY: 'SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  GITHUB_PAT: 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  SLACK_TOKEN: 'xoxb-FAKE-TOKEN-FOR-TESTING-DEMO',

  // Misc
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'admin123',

  DEBUG: true,
};
