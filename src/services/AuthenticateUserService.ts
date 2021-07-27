import { getRepository } from 'typeorm';
import User from '../models/User';
import { compare } from 'bcryptjs'
import { sign, verify } from 'jsonwebtoken'

interface Request {
  email:string;
  password:string;
}

interface Response{
  user: User;
  token:string;
}


  class AuthenticateUserService{
  public async execute ({ email, password}:Request): Promise<Response>{
    const usersRepository = getRepository(User);

    const user =  await usersRepository.findOne({ where: { email } });

    if(!user){
      throw new Error('Incorrect email/password combination');
    }

    // user.password - senha criptografada no banco
    // password- senha recebida no front, não-criptografada
    const passwordMatched = await compare(password, user.password);

    if(!passwordMatched){
      throw new Error('Incorrect email/password combination');
    }

    // chegou ate aqui, informações corretas e usuario autenticado!
    //criando token
    const token = sign({}, 'da9d160e4d9f5ff9adc78159a7884ff7', {
      subject: user.id,
      expiresIn:'1d',
    })

    return{
      user,
      token,
    };

  }

}

export default AuthenticateUserService;
