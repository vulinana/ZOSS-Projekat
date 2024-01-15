/* eslint-disable */
import { Module } from '@nestjs/common';
import { WebhookController } from './webhook.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { PullRequest, PullRequestSchema } from './pull-request.model';
import { PullRequestService } from './pull-request.service';
import { AuthService } from './auth.service';
import { HashingService } from './hashing.service';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { JwtGuard } from './strategies/jwt.guard';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  controllers: [WebhookController, AuthController],
  providers: [PullRequestService, AuthService, HashingService, JwtStrategy],
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: 100000000
        }
      })
    }),
    ConfigModule,
    MongooseModule.forFeature([
      {
        name: PullRequest.name,
        schema: PullRequestSchema
      }
    ])
  ]
})
export class WebhookModule {}
