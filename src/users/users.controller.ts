import { BadRequestException, Body, Controller, Post } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {

    constructor(private readonly usersService: UsersService) { }

    @Post('register')
    async register(@Body() body: { email: string, password: string }) {
        const { email, password } = body;

        const existingUser = await this.usersService.findUserByEmail(email);
        if (existingUser) {
            throw new BadRequestException('User already exists');
        }

        return this.usersService.createUser(email, password);
    }

}
