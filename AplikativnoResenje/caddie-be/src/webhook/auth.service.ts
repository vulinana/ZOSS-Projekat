import {
  BadRequestException,
  Injectable,
  NotFoundException
} from '@nestjs/common';
import { HashingService } from './hashing.service';
import { JwtService } from '@nestjs/jwt';

export class User {
  constructor(
    public readonly username: string,
    public readonly email: string,
    private _password: string
  ) {}

  setPassword(newPassword: string) {
    this._password = newPassword;
  }

  get password() {
    return this._password;
  }
}

@Injectable()
export class AuthService {
  private users: { [key: string]: User } = {};
  constructor(
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService
  ) {}

  getUser(email: string) {
    return this.users[email];
  }

  async login(email: string, password: string): Promise<string> {
    const user = this.users[email];
    if (!user) throw new NotFoundException("User doesn't exist!");
    const isPasswordValid = await this.hashingService.comparePassword(
      password,
      user.password
    );
    console.log(password, user.password, isPasswordValid);
    if (!isPasswordValid) throw new BadRequestException('Credentials wrong!');
    return this.jwtService.sign({ email });
  }

  async register(user: User): Promise<void> {
    const exists = this.users[user.email];
    if (exists) throw new Error('User already exists!');
    const hashedPassword = await this.hashingService.hashPassword(
      user.password
    );
    user.setPassword(hashedPassword);
    this.users[user.email] = user;
  }
}
