import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';

export class RegisterDto {
    @ApiProperty({ example: 'user@example.com', description: 'User email address' })
    @IsEmail()
    email: string;

    @ApiProperty({ example: 'password123', description: 'User password', minLength: 6 })
    @IsNotEmpty()
    @MinLength(6)
    password: string;

    @ApiProperty({ example: ['user'], description: 'Roles assigned to the user', required: false })
    @IsOptional()
    roles?: string[];

    @ApiProperty({ example: ['Serkan'], description: 'Firstname assigned to the user', required: false })
    @IsOptional()
    firstName: string;

    @ApiProperty({ example: ['Ozdemir'], description: 'Lastname assigned to the user', required: false })
    @IsOptional()
    lastName: string;

    @ApiProperty({ example: ['url'], description: 'avatar assigned to the user', required: false })
    @IsOptional()
    avatarUrl: string;

    @ApiProperty({ example: '1234567890', description: 'Google ID', required: false })
    @IsOptional()
    @IsString()
    googleId?: string;
}
