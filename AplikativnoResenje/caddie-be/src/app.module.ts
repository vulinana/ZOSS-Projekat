import { Module } from '@nestjs/common';
import { UserModule } from './users/user.module';
import { PrismaService } from './prisma.service';
import { ConfigModule } from '@nestjs/config';
import { AwsModule } from './aws/aws.module';

@Module({
  imports: [ConfigModule.forRoot(), AwsModule, UserModule],
  providers: [PrismaService],
})
export class AppModule {}
