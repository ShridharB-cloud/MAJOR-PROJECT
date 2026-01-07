import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardFooter,
    CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

interface SignInFormData {
    email: string;
    password: string;
    rememberMe: boolean;
}

interface FormErrors {
    email?: string;
    password?: string;
    rememberMe?: string;
    general?: string;
}

interface SignInBlockProps {
    onNavigate: (view: 'signup' | 'home' | 'scanner') => void;
    onLogin: () => void;
}

const SignInBlock = ({ onNavigate, onLogin }: SignInBlockProps) => {
    const [formData, setFormData] = useState<SignInFormData>({
        email: "",
        password: "",
        rememberMe: false,
    });
    const [errors, setErrors] = useState<FormErrors>({});
    const [isLoading, setIsLoading] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    const validateForm = (): boolean => {
        const newErrors: FormErrors = {};

        if (!formData.email.trim()) {
            newErrors.email = "Email is required";
        } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            newErrors.email = "Please enter a valid email address";
        }

        if (!formData.password) {
            newErrors.password = "Password is required";
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleInputChange = (
        field: keyof SignInFormData,
        value: string | boolean
    ) => {
        setFormData((prev) => ({
            ...prev,
            [field]: value,
        }));

        if (errors[field]) {
            setErrors((prev) => ({
                ...prev,
                [field]: undefined,
            }));
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        if (!validateForm()) return;

        setIsLoading(true);
        setErrors({});

        // 🔹 Simulate a fake request
        setTimeout(() => {
            console.log("Form submitted:", formData);

            // Specific validation for admin@gmail.com
            if (formData.email === "admin@gmail.com" && formData.password === "admin123") {
                if (formData.rememberMe) {
                    localStorage.setItem("rememberMe", "true");
                }
                // alert("Signed in successfully (demo only)");
                // alert("Signed in successfully (demo only)");
                onLogin();
                onNavigate('home');
            } else {
                setErrors({
                    general: "Invalid email or password",
                    password: " " // Highlight password field
                });
            }

            setIsLoading(false);
        }, 1000);
    };

    return (
        <Card className="w-full max-w-[400px] mx-auto flex flex-col gap-6 bg-zinc-950 border-zinc-800 text-zinc-100 shadow-xl">
            <CardHeader className="text-center space-y-2 pb-2">
                <CardTitle className="text-2xl font-bold tracking-tight text-white">Welcome Back</CardTitle>
                <CardDescription className="text-zinc-400">Sign in to your account to continue</CardDescription>
            </CardHeader>

            <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                <CardContent className="flex flex-col gap-4">
                    {errors.general && (
                        <div className="p-3 text-sm text-red-500 bg-red-500/10 border border-red-500/20 rounded-md">
                            {errors.general}
                        </div>
                    )}

                    <div className="flex flex-col gap-2">
                        <Label htmlFor="email" className="text-zinc-200 font-medium">Email</Label>
                        <Input
                            id="email"
                            type="email"
                            placeholder="john.doe@example.com"
                            className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                            value={formData.email}
                            onChange={(e) => handleInputChange("email", e.target.value)}
                            disabled={isLoading}
                        />
                        {errors.email && (
                            <p className="text-sm text-red-500">{errors.email}</p>
                        )}
                    </div>

                    <div className="flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                            <Label htmlFor="password" className="text-zinc-200 font-medium">Password</Label>
                            <a
                                href="#"
                                className="text-sm text-blue-500 hover:text-blue-400 font-medium hover:underline transition-colors"
                            >
                                Forgot password?
                            </a>
                        </div>
                        <div className="relative">
                            <Input
                                id="password"
                                type={showPassword ? "text" : "password"}
                                placeholder="Enter your password"
                                className="bg-zinc-900 border-zinc-700 text-white placeholder:text-zinc-500 pr-10 focus-visible:ring-blue-600 focus-visible:border-blue-600"
                                value={formData.password}
                                onChange={(e) => handleInputChange("password", e.target.value)}
                                disabled={isLoading}
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-300 transition-colors"
                            >
                                {showPassword ? (
                                    <EyeOff className="h-4 w-4" />
                                ) : (
                                    <Eye className="h-4 w-4" />
                                )}
                            </button>
                        </div>
                        {errors.password && (
                            <p className="text-sm text-red-500">{errors.password}</p>
                        )}
                    </div>

                    <div className="flex items-center justify-between pt-2">
                        <div className="flex items-center space-x-2">
                            <Checkbox
                                id="rememberMe"
                                checked={formData.rememberMe}
                                onCheckedChange={(checked) =>
                                    handleInputChange("rememberMe", checked === true)
                                }
                                className="border-zinc-600 data-[state=checked]:bg-blue-600 data-[state=checked]:text-white data-[state=checked]:border-blue-600"
                            />
                            <Label htmlFor="rememberMe" className="text-sm text-zinc-400 font-normal cursor-pointer">
                                Remember me
                            </Label>
                        </div>
                    </div>
                </CardContent>

                <CardFooter className="flex flex-col gap-6 pt-0">
                    <Button
                        type="submit"
                        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold h-11 transition-all duration-200"
                        disabled={isLoading}
                    >
                        {isLoading ? "Signing In..." : "Sign In"}
                    </Button>

                    <div className="text-center">
                        <p className="text-sm text-zinc-400">
                            Don't have an account?{" "}
                            <button
                                type="button"
                                onClick={() => onNavigate('signup')}
                                className="text-white hover:underline font-medium transition-colors"
                            >
                                Sign Up
                            </button>
                        </p>
                    </div>
                </CardFooter>
            </form>
        </Card>
    );
};

export default SignInBlock;
