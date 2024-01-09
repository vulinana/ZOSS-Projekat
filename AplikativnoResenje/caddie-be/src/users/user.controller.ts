import { Body, Controller, Get, Patch, Res } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Patch('change-password')
  async changePassword(@Body() body: { id: string, nova_sifra: string }, @Res() res) {
    try {
      await this.userService.changePassword(body.id, body.nova_sifra);
      return res.status(200).json({ message: 'Uspešna promena lozinke' });
    } catch (error) {
      return res.status(500).json({ message: 'Greška prilikom promene lozinke', error: error.message });
    }  
  } 
} 