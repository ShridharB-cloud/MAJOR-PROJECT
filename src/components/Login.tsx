import SignInBlock from './SignInBlock';

interface LoginProps {
    onNavigate: (view: 'signup') => void;
}

const Login = ({ onNavigate }: LoginProps) => {
    return (
        <div className="min-h-[calc(100vh-80px)] grid place-items-center p-4">
            <SignInBlock onNavigate={onNavigate} />
        </div>
    );
};

export default Login;
