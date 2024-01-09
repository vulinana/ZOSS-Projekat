import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async changePassword(id: string, nova_sifra: string){
    console.log("CALL promeni_sifru('" + id + "', '" + nova_sifra + "')")
    await this.prisma.$queryRawUnsafe(
      "CALL promeni_sifru('" + id + "', '" + nova_sifra + "')"
   )
  }

}