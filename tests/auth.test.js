process.env.DATABASE_URL =
  process.env.DATABASE_URL_TEST ||
  'postgresql://auth_user:devpassword@localhost:5432/breezy_auth_test';
process.env.JWT_SECRET = 'test-jwt-secret-do-not-use-in-prod';
process.env.INTERNAL_SECRET = 'test-internal-secret';
process.env.USER_SERVICE_URL = 'http://localhost:3002';
process.env.JWT_EXPIRES_IN = '15m';
process.env.BCRYPT_ROUNDS = '4';
process.env.REFRESH_TOKEN_DAYS = '7';

jest.mock('axios', () => ({ post: jest.fn(), get: jest.fn() }));

const request = require('supertest');
const axios = require('axios');
const app = require('../src/app');
const { sequelize } = require('../src/config/database');
const User = require('../src/models/user.model');
const RefreshToken = require('../src/models/refreshToken.model');
const { hashToken } = require('../src/utils/jwt.utils');

const VALID_USER = {
  username: 'testuser',
  email: 'test@example.com',
  password: 'Password1',
};

beforeAll(async () => {
  await sequelize.authenticate();
  await sequelize.sync({ force: true });
});

afterAll(async () => {
  await sequelize.close();
});

beforeEach(async () => {
  await RefreshToken.destroy({ where: {} });
  await User.destroy({ where: {} });
  axios.post.mockResolvedValue({ data: { ok: true } });
});

describe('POST /auth/register', () => {
  it('succès avec données valides → 201 + user + token', async () => {
    const res = await request(app).post('/auth/register').send(VALID_USER);

    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      username: 'testuser',
      email: 'test@example.com',
      role: 'user',
    });
    expect(res.body.token).toBeDefined();
  });

  it('email déjà pris → 409 EMAIL_TAKEN', async () => {
    await request(app).post('/auth/register').send(VALID_USER);

    const res = await request(app)
      .post('/auth/register')
      .send({ ...VALID_USER, username: 'otheruser' });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('EMAIL_TAKEN');
  });

  it('username déjà pris → 409 USERNAME_TAKEN', async () => {
    await request(app).post('/auth/register').send(VALID_USER);

    const res = await request(app)
      .post('/auth/register')
      .send({ ...VALID_USER, email: 'other@example.com' });

    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('USERNAME_TAKEN');
  });

  it('password trop court → 400 VALIDATION_ERROR', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ ...VALID_USER, password: 'Short1' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('email invalide → 400 VALIDATION_ERROR', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ ...VALID_USER, email: 'not-an-email' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });
});

describe('POST /auth/login', () => {
  beforeEach(async () => {
    await request(app).post('/auth/register').send(VALID_USER);
  });

  it('succès → 200 + token', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: VALID_USER.email, password: VALID_USER.password });

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.email).toBe(VALID_USER.email);
  });

  it('mauvais mot de passe → 401 INVALID_CREDENTIALS', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: VALID_USER.email, password: 'WrongPassword1' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('email inexistant → 401 INVALID_CREDENTIALS', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({ email: 'nobody@example.com', password: 'Password1' });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('POST /auth/refresh', () => {
  it('token valide → 200 + nouveau token', async () => {
    const agent = request.agent(app);
    await agent.post('/auth/register').send(VALID_USER);

    const res = await agent.post('/auth/refresh');

    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
  });

  it('token révoqué → 401 INVALID_REFRESH_TOKEN', async () => {
    const registerRes = await request(app).post('/auth/register').send(VALID_USER);
    const setCookie = registerRes.headers['set-cookie'][0];
    const rawToken = setCookie.match(/refreshToken=([^;]+)/)[1];

    await RefreshToken.update(
      { is_revoked: true },
      { where: { token_hash: hashToken(rawToken) } },
    );

    const res = await request(app)
      .post('/auth/refresh')
      .send({ refreshToken: rawToken });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_REFRESH_TOKEN');
  });
});

describe('POST /auth/logout', () => {
  it('révoque le token → 204', async () => {
    const agent = request.agent(app);
    await agent.post('/auth/register').send(VALID_USER);

    const res = await agent.post('/auth/logout');

    expect(res.status).toBe(204);

    const active = await RefreshToken.count({ where: { is_revoked: false } });
    expect(active).toBe(0);
  });
});

describe('POST /auth/internal/ban', () => {
  it('sans INTERNAL_SECRET → 401', async () => {
    const res = await request(app)
      .post('/auth/internal/ban')
      .send({ userId: 'aaaaaaaa-0000-0000-0000-000000000000' });

    expect(res.status).toBe(401);
  });

  it('avec bon INTERNAL_SECRET → 200 et utilisateur banni', async () => {
    const user = await User.create({
      username: 'targetuser',
      email: 'target@example.com',
      password_hash: 'placeholder-hash',
    });

    const res = await request(app)
      .post('/auth/internal/ban')
      .set('x-internal-secret', process.env.INTERNAL_SECRET)
      .send({ userId: user.id });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    await user.reload();
    expect(user.is_banned).toBe(true);
  });
});
