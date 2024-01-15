import { Module } from '@nestjs/common';
import { UserModule } from './users/user.module';
import { PrismaService } from './prisma.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AwsModule } from './aws/aws.module';
import { WebhookModule } from './webhook/webhook.module';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    ConfigModule.forRoot(),
    AwsModule,
    UserModule,
    WebhookModule,
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return {
          uri: configService.get('MONGOOSE_DATABASE_URL'),
          useNewUrlParser: true,
          useUnifiedTopology: true
        };
      }
    })
  ],
  providers: [PrismaService]
})
export class AppModule {}
