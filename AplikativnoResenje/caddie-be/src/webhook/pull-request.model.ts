import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type PullRequestDocument = HydratedDocument<PullRequest>;

@Schema()
export class PullRequest {
  @Prop()
  githubId: string;
  @Prop()
  number: number;
  @Prop()
  title: string;
  @Prop()
  body: string;
}

export const PullRequestSchema = SchemaFactory.createForClass(PullRequest);
