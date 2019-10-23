import jwt from 'jsonwebtoken';
import { promisify } from 'util';
import authConfig from '../../config/auth';

export default async (req, res, next) => {
  const headerAuth = req.headers.authorization;

  if (!headerAuth) {
    return res.status(401).json({ error: 'Token not provided' });
  }

  const [, token] = headerAuth.split(' ');

  try {
    const decoded = await promisify(jwt.verify)(token, authConfig.secret);
    req.userId = decoded.id;
  } catch (err) {
    // console.log('err', err);
    return res.status(401).json({ error: 'Token invalid' });
  }

  return next();
};
