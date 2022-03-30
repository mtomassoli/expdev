#define _USE_MATH_DEFINES
#include <cmath>
#include <cstdio>

class Figure {
public:
    virtual double getArea() = 0;
};

class Rectangle : public Figure {
    double base, height;

public:
    Rectangle(double base, double height) : base(base), height(height) {}

    virtual double getArea() {
        return base * height;
    }
};

class Circle : public Figure {
    double radius;

public:
    Circle(double radius) : radius(radius) {}

    virtual double getArea() {
        return radius * M_PI;
    }
};

int main() {
    Figure *figures[] = { new Rectangle(10, 5), new Circle(1.5), new Rectangle(5, 10) };

    for (Figure *f : figures)
        printf("area: %lf\n", f->getArea());

    return 0;
}
