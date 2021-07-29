import {Request, Response, NextFunction} from 'express'
import { verify } from 'jsonwebtoken';
import authConfig from '../config/auth';
import AppError from '../errors/AppError'

interface TokenPayload{
  iat:number;
  exp:number;
  sub:string;
}

export default function ensureAuthenticated(request: Request, response: Response, next: NextFunction): void{
  //validação do token jwt
  const authHeader = request.headers.authorization;

  if(!authHeader){
    throw new AppError('JWT token in missig', 401);
  }

  //Bearer sauadasd...
  const [ type, token ] = authHeader.split(' ');


  try{
    const decoded = verify(token, authConfig.jwt.secret);

    const { sub } = decoded as TokenPayload;

    request.user = {
      id:sub,
    }

    // console.log(decoded);
    return next();

  }catch( err ) {
    throw new AppError('Invalid JWT token', 401);
  }

}
