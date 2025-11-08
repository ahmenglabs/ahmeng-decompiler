import React, { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';

interface DecompileResult {
  filename: string;
  status: 'success' | 'error';
  decompiled_code?: string;
  error?: string;
}

interface DecompilerProps {
  token: string;
  onLogout: () => void;
}

function Decompiler({ token, onLogout }: DecompilerProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [results, setResults] = useState<DecompileResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const newFiles = Array.from(e.dataTransfer.files);
      setFiles(prev => [...prev, ...newFiles]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const newFiles = Array.from(e.target.files);
      setFiles(prev => [...prev, ...newFiles]);
    }
  };

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (files.length === 0) return;

    setLoading(true);
    const formData = new FormData();
    files.forEach(file => {
      formData.append('files', file);
    });

    try {
      const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || '';
      const response = await fetch(`${apiBaseUrl}/api/decompile`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();
      if (response.ok) {
        setResults(data.results);
      } else {
        alert(data.error || 'An error occurred');
      }
    } catch {
      alert('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Ahmeng Decompiler</h1>
          <Button onClick={onLogout} variant="outline">Logout</Button>
        </div>

        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Upload Files for Decompilation</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div
                className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                  dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
                }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                <Textarea
                  placeholder="Drag and drop files here, or click to select files..."
                  className="min-h-32 resize-none cursor-pointer"
                  readOnly
                  onClick={() => fileInputRef.current?.click()}
                />
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <p className="text-sm text-gray-500 mt-2">
                  Supports all file types and sizes
                </p>
              </div>

              {files.length > 0 && (
                <div className="space-y-2">
                  <h3 className="font-medium">Selected Files:</h3>
                  {files.map((file, index) => (
                    <div key={index} className="flex items-center justify-between bg-gray-100 p-2 rounded">
                      <span className="text-sm">{file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => removeFile(index)}
                      >
                        Remove
                      </Button>
                    </div>
                  ))}
                </div>
              )}

              <Button type="submit" disabled={loading || files.length === 0} className="w-full">
                {loading ? 'Decompiling...' : `Decompile ${files.length} File${files.length !== 1 ? 's' : ''}`}
              </Button>
            </form>
          </CardContent>
        </Card>

        {results.length > 0 && (
          <div className="space-y-4">
            <h2 className="text-2xl font-bold">Results</h2>
            {results.map((result, index) => (
              <Card key={index}>
                <CardHeader>
                  <CardTitle className={result.status === 'error' ? 'text-red-600' : 'text-green-600'}>
                    {result.filename} - {result.status === 'success' ? 'Success' : 'Error'}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {result.status === 'success' ? (
                    <Textarea
                      value={result.decompiled_code}
                      readOnly
                      className="min-h-96 font-mono text-sm"
                    />
                  ) : (
                    <p className="text-red-600">{result.error}</p>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default Decompiler;