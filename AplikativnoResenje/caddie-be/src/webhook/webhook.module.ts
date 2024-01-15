/* eslint-disable */
import { Module } from '@nestjs/common';
import { WebhookController } from './webhook.controller';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { PullRequest, PullRequestSchema } from './pull-request.model';
import { PullRequestService } from './pull-request.service';

@Module({
  controllers: [WebhookController],
  providers: [PullRequestService],
  imports: [
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
