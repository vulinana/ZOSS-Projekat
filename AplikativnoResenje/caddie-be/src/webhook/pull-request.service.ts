/*eslint-disable */
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { PullRequest } from './pull-request.model';
import { Model } from 'mongoose';
import { PrDto } from './dtos/pr.dto';

@Injectable()
export class PullRequestService {
  constructor(
    @InjectModel(PullRequest.name)
    private readonly pullRequestModel: Model<PullRequest>
  ) {}

  async save({ number, title, body, githubId, author }: PrDto) {
    const newPr = new this.pullRequestModel({
      author,
      number,
      title,
      body,
      githubId
    });
    await newPr.save();
  }

  findAll() {
    return this.pullRequestModel.find({});
  }

  async getAllByAuthor(author: string) {
    const result = await this.pullRequestModel.find({
      author
    });
    return result;
  }
}
