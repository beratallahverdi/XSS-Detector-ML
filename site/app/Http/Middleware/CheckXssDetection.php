<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;

class CheckXssDetection
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $post = $request->all();
        $checkString = '';
        if(!empty($post))
            $checkString = urlencode(json_encode($post));
        $output=null;
        $retval=null;
        switch(PHP_OS){
            case "WINNT":
                $output = self::execute(`python.exe C:\Dev\Projects\ML-XSS-Detection-main\xss\classifiers.py --xss_detection '{$checkString}'`);
                break;
        }
        if(stripos($output, 'reject') !== false){
            return response()->json(['error' => 'XSS Detected'], 403);
        }
        return $next($request);
    }

    private static function execute($cmd): string
    {
        $process = Process::fromShellCommandline($cmd);

        $processOutput = '';

        $captureOutput = function ($type, $line) use (&$processOutput) {
            $processOutput .= $line;
        };

        $process->setTimeout(null)
            ->run($captureOutput);

        if ($process->getExitCode()) {
            $exception = new Exception('Shell Error');
        }

        return $processOutput;
    }
}
