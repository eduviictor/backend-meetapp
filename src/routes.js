import { Router } from 'express';
import UserController from './app/controllers/UserController';

import authMiddleware from './app/middlewares/auth';
import SessionController from './app/controllers/SessionController';

const routes = new Router();

routes.post('/users', UserController.store);
routes.get('/users', UserController.show);
routes.post('/sessions', SessionController.store);

routes.use(authMiddleware);
routes.put('/users', UserController.update);

export default routes;
