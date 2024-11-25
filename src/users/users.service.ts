import { Injectable } from '@nestjs/common';
import { User } from './shemas/user.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) { }

    async createUser(email: string, password: string): Promise<User> {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new this.userModel({ email, password: hashedPassword });
        return newUser.save();
    }

    async findUserByEmail(email: string): Promise<User | null>{
        return this.userModel.findOne({email}).exec();
    }

}
