import { Body, Controller, Post } from '@nestjs/common';
import { AuthService, User } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  async register(
    @Body()
    {
      email,
      username,
      password
    }: {
      email: string;
      username: string;
      password: string;
    }
  ) {
    await this.authService.register(new User(username, email, password));
    return { status: 'SUCCESS' };
  }

  @Post('/login')
  async login(
    @Body() { email, password }: { email: string; password: string }
  ) {
    const jwt = await this.authService.login(email, password);
    return { accessToken: jwt };
  }
}
