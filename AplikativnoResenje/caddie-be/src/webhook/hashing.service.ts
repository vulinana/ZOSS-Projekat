import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
@Injectable()
export class HashingService {
  comparePassword(
    password: string,
    existingPassword: string
  ): Promise<boolean> {
    return (
      password && existingPassword && bcrypt.compare(password, existingPassword)
    );
  }

  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  async generateVerificationToken(): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(Date.now().toString(), saltRounds);
  }

  async verifyVerificationToken(
    token: string,
    storedToken: string
  ): Promise<boolean> {
    if (!token || !storedToken || token === '' || storedToken === '')
      return false;
    return await bcrypt.compare(token ?? '', storedToken);
  }

  async generateInvitationToken(): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(Date.now().toString(), saltRounds);
  }

  async generateForgotPasswordToken(): Promise<string> {
    const saltRounds = 10;
    return await bcrypt.hash(Date.now().toString(), saltRounds);
  }
}
